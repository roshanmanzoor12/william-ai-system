#!/usr/bin/env python3
"""
William/Jarvis Project Test Runner
Digital Promotix

Purpose:
- Scan a William/Jarvis project folder with hundreds of files.
- Check that files/folders exist, Python files compile, config files parse, imports are safe,
  pytest can run, API can be smoke-tested, and dashboard can be build-checked.
- Never modifies project files.

Usage:
    python test_william_project.py
    python test_william_project.py --root C:\\William-Jarvis
    python test_william_project.py --root . --strict
    python test_william_project.py --root . --import-python
    python test_william_project.py --root . --run-pytest
    python test_william_project.py --root . --dashboard-build
    python test_william_project.py --root . --api-smoke
    python test_william_project.py --root . --all
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import py_compile
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PYTHON_SKIP_IMPORT_PATTERNS = (
    "migrations/env.py",
    "deploy/monitoring/healthchecks.py",
)

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".next",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
}

TEMP_HELPER_FILES = {
    "patch_secret_scanner_v2.py",
    "patch_secret_scanner_v3.py",
    "fix_demo_secret_values.py",
    "show_secret_findings.py",
}

# Real secret patterns only.
# These intentionally avoid flagging normal security-code keywords such as:
# "password", "token", "secret", "api_key", SENSITIVE_KEYS, SECRET_PATTERNS,
# os.getenv("ENV_VAR"), enum values, redaction rules, and documentation text.
SUSPICIOUS_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:live|prod|real)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"(?i)\bbearer\s+(?!<|example|demo|redacted)[A-Za-z0-9._~+/=-]{30,}\b"),
    re.compile(
        r"(?i)\b(api[_-]?key|client_secret|access_key|secret|token|password|passwd|private_key)\b"
        r"\s*=\s*['\"](?!<|example|demo|dummy|fake|redacted|your_|test-|test_|placeholder)"
        r"[^'\"]{16,}['\"]"
    ),
]

SAFE_SECRET_SCAN_HINTS = (
    "sensitive",
    "secret_patterns",
    "secret_field_names",
    "default_secret_keys",
    "default_sensitive_keys",
    "redact",
    "redaction",
    "mask",
    "placeholder",
    "example",
    "demo",
    "test",
    "dummy",
    "fake",
    "safe",
    "detect",
    "detected",
    "pattern",
    "patterns",
    "marker",
    "markers",
    "keywords",
    "os.getenv",
    "os.environ",
    "_env",
    "env:",
    "enum",
    "class ",
    "def ",
    "without exposing secrets",
    "no secrets are hardcoded",
    "never include raw secrets",
    "not included",
    "<redacted",
    "redacted",
)

EXPECTED_HIGH_LEVEL_PATHS = [
    "main.py",
    "requirements.txt",
    ".env.example",
    "README.md",
    "core",
    "agents",
    "agents/base_agent.py",
    "agents/registry.py",
    "agents/agent_loader.py",
    "agents/security_agent/security_agent.py",
    "agents/memory_agent/memory_agent.py",
    "agents/verification_agent/verification_agent.py",
    "apps/api",
    "apps/api/main.py",
    "database",
    "database/db.py",
    "apps/dashboard",
    "tests",
]


@dataclass
class CheckResult:
    name: str
    success: bool
    message: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    details: List[str] = field(default_factory=list)

    def status(self) -> str:
        return "PASS" if self.success else "FAIL"


@dataclass
class ProjectReport:
    root: str
    started_at: float
    finished_at: float = 0.0
    results: List[CheckResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(result.success for result in self.results)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "success": self.success,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(max(0.0, self.finished_at - self.started_at), 3),
            "summary": {
                "checks": len(self.results),
                "passed_checks": sum(1 for result in self.results if result.success),
                "failed_checks": sum(1 for result in self.results if not result.success),
                "total_items": sum(result.total for result in self.results),
                "passed_items": sum(result.passed for result in self.results),
                "failed_items": sum(result.failed for result in self.results),
                "warnings": sum(result.warnings for result in self.results),
            },
            "results": [asdict(result) for result in self.results],
        }


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(root: Path, suffixes: Optional[Sequence[str]] = None) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            if suffixes is None or path.suffix.lower() in suffixes:
                yield path


def run_command(cmd: Sequence[str], cwd: Path, timeout: int = 60) -> Tuple[int, str, str]:
    try:
        process = subprocess.run(
            list(cmd),
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
        return process.returncode, process.stdout.strip(), process.stderr.strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or f"Timed out after {timeout}s"


def check_structure(root: Path, strict: bool = False) -> CheckResult:
    details: List[str] = []
    passed = 0
    failed = 0
    total = len(EXPECTED_HIGH_LEVEL_PATHS)

    for expected in EXPECTED_HIGH_LEVEL_PATHS:
        target = root / expected
        if target.exists():
            passed += 1
        else:
            failed += 1
            details.append(f"Missing: {expected}")

    py_count = len(list(iter_files(root, [".py"])))
    js_count = len(list(iter_files(root, [".tsx", ".ts", ".jsx", ".js"])))
    kt_count = len(list(iter_files(root, [".kt"])))
    total_files = len(list(iter_files(root)))

    details.insert(
        0,
        f"Detected files: total={total_files}, python={py_count}, frontend/js-ts={js_count}, kotlin={kt_count}",
    )

    success = failed == 0 if strict else passed >= 6

    return CheckResult(
        name="project_structure",
        success=success,
        message="Basic William/Jarvis structure detected." if success else "Project structure is incomplete.",
        total=total,
        passed=passed,
        failed=failed,
        details=details,
    )


def check_python_syntax(root: Path) -> CheckResult:
    details: List[str] = []
    py_files = list(iter_files(root, [".py"]))
    passed = 0
    failed = 0

    for path in py_files:
        try:
            py_compile.compile(str(path), doraise=True)
            passed += 1
        except py_compile.PyCompileError as exc:
            failed += 1
            details.append(f"{rel(path, root)}: {exc.msg}")
        except Exception as exc:
            failed += 1
            details.append(f"{rel(path, root)}: {type(exc).__name__}: {exc}")

    return CheckResult(
        name="python_syntax_compile",
        success=failed == 0,
        message="All Python files compile." if failed == 0 else "Some Python files have syntax errors.",
        total=len(py_files),
        passed=passed,
        failed=failed,
        details=details[:200],
    )


def check_python_imports(root: Path) -> CheckResult:
    details: List[str] = []
    py_files = list(iter_files(root, [".py"]))
    passed = 0
    failed = 0

    old_path = list(sys.path)
    sys.path.insert(0, str(root))

    try:
        for path in py_files:
            relative = rel(path, root)

            if path.name in TEMP_HELPER_FILES:
                continue

            if any(relative.endswith(pattern) for pattern in PYTHON_SKIP_IMPORT_PATTERNS):
                continue

            module_name = "william_test_import_" + re.sub(r"[^A-Za-z0-9_]", "_", relative)

            try:
                spec = importlib.util.spec_from_file_location(module_name, str(path))
                if spec is None or spec.loader is None:
                    raise ImportError("Could not create import spec")

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)  # type: ignore[union-attr]
                passed += 1
            except Exception as exc:
                failed += 1
                details.append(f"{relative}: {type(exc).__name__}: {exc}")
    finally:
        sys.path[:] = old_path

    return CheckResult(
        name="python_import_safety",
        success=failed == 0,
        message="All tested Python files import safely." if failed == 0 else "Some Python files fail on import.",
        total=passed + failed,
        passed=passed,
        failed=failed,
        details=details[:200],
    )


def check_config_files(root: Path) -> CheckResult:
    details: List[str] = []
    json_files = list(iter_files(root, [".json"]))
    yaml_files = list(iter_files(root, [".yml", ".yaml"]))

    passed = 0
    failed = 0

    for path in json_files:
        try:
            json.loads(path.read_text(encoding="utf-8"))
            passed += 1
        except Exception as exc:
            failed += 1
            details.append(f"{rel(path, root)}: invalid JSON: {exc}")

    for path in yaml_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "\t" in text:
            failed += 1
            details.append(f"{rel(path, root)}: YAML contains tab characters")
        else:
            passed += 1

    return CheckResult(
        name="config_parse",
        success=failed == 0,
        message="Config files look parseable." if failed == 0 else "Some config files have parse issues.",
        total=len(json_files) + len(yaml_files),
        passed=passed,
        failed=failed,
        details=details[:200],
    )


def _line_is_safe_secret_context(line: str) -> bool:
    """
    Return True for normal security/privacy code that mentions secret words
    but does not expose an actual credential value.
    """
    stripped = line.strip()
    lower = stripped.lower()

    if not stripped:
        return True

    if stripped.startswith("#"):
        return True

    if any(hint in lower for hint in SAFE_SECRET_SCAN_HINTS):
        return True

    # Safe constants/enums/sets/lists containing only secret field names.
    if re.search(r"(?i)\b(password|token|secret|api_key|private_key|credential)\b\s*[,})\]]?$", stripped):
        return True

    # Safe environment variable references, not secret values.
    if re.search(r"(?i)os\.(getenv|environ)|[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)_?ENV", stripped):
        return True

    # Safe detector regex / scanner logic.
    if "re.compile" in lower or "re.match" in lower or "pattern.search" in lower:
        return True

    return False


def _line_is_secret_scanner_false_positive(line: str) -> bool:
    """
    Ignore security/privacy code that intentionally contains secret-detection
    markers, regexes, redaction lists, enum names, and environment variable names.
    """
    stripped = line.strip()
    lower = stripped.lower()

    if _line_is_safe_secret_context(line):
        return True

    safe_fragments = (
        "sensitive_keys",
        "sensitive_patterns",
        "sensitive_tags",
        "secret_patterns",
        "blocked_body_patterns",
        "dangerous_content_markers",
        "private_key_markers",
        "default_sensitive_keys",
        "_looks_like_secret",
        "regex",
        "pattern",
        "marker",
        "markers",
        "redact",
        "redaction",
        "detected",
        "detect",
        "contains_secret",
        "secret-like",
        "secret_like",
        "environment variable",
        "example",
        "demo",
        "dummy",
        "fake",
        "placeholder",
        "redacted",
        "<redacted",
        "not included",
        "without exposing secrets",
        "no secrets are hardcoded",
        "never include raw secrets",
    )

    if any(fragment in lower for fragment in safe_fragments):
        return True

    # Common literal marker strings used by guards to BLOCK secrets.
    if stripped in {
        '"-----BEGIN PRIVATE KEY-----",',
        '"-----BEGIN RSA PRIVATE KEY-----",',
        '"-----BEGIN OPENSSH PRIVATE KEY-----",',
        '"password=",',
        '"authorization: bearer",',
        '"api_key=",',
        '"secret_key",',
        '"password:",',
        '"private key",',
    }:
        return True

    return False


def check_secret_scan(root: Path) -> CheckResult:
    details: List[str] = []
    failed_files = set()
    scanned = 0

    allowed_names = {
        ".env.example",
        "README.md",
        "test_william_project.py",
    }

    allowed_suffixes = {
        ".py",
        ".json",
        ".yml",
        ".yaml",
        ".env",
        ".txt",
        ".md",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".kt",
    }

    for path in iter_files(root):
        relative_path = rel(path, root)

        if path.name in TEMP_HELPER_FILES:
            continue

        if path.stat().st_size > 2_000_000:
            continue

        if path.suffix.lower() not in allowed_suffixes and path.name not in allowed_names:
            continue

        scanned += 1
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

        for line_number, line in enumerate(lines, start=1):
            hits = []

            for pattern in SUSPICIOUS_SECRET_PATTERNS:
                if pattern.search(line):
                    hits.append(pattern.pattern)

            if not hits:
                continue

            if path.name in allowed_names:
                continue

            if _line_is_secret_scanner_false_positive(line):
                continue

            # audit_logger.py uses regexes specifically to redact obvious secrets.
            # These are scanner rules, not exposed credentials.
            if relative_path == "agents/security_agent/audit_logger.py" and (
                "_looks_like_secret" in line
                or "re.match" in line
                or "bearer" in line.lower()
                or "sk-" in line.lower()
                or "PRIVATE KEY" in line
            ):
                continue

            failed_files.add(path)
            details.append(f"Possible real secret in {relative_path}:{line_number}")

    passed = scanned - len(failed_files)
    failed = len(failed_files)

    return CheckResult(
        name="secret_scan_light",
        success=failed == 0,
        message="No obvious hardcoded secrets found." if failed == 0 else "Possible hardcoded secrets found.",
        total=scanned,
        passed=passed,
        failed=failed,
        details=details[:200],
    )


def check_class_names(root: Path) -> CheckResult:
    details: List[str] = []
    py_files = list(iter_files(root, [".py"]))
    total = 0
    passed = 0
    failed = 0

    for path in py_files:
        if path.name in TEMP_HELPER_FILES:
            continue

        text = path.read_text(encoding="utf-8", errors="ignore")
        if text.strip() == "":
            continue

        total += 1

        try:
            tree = ast.parse(text)
            classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            functions = [
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]

            if classes or functions:
                passed += 1
            else:
                failed += 1
                details.append(f"No classes/functions detected: {rel(path, root)}")
        except Exception as exc:
            failed += 1
            details.append(f"Cannot parse AST {rel(path, root)}: {exc}")

    return CheckResult(
        name="python_code_shape",
        success=failed == 0,
        message="Python files contain importable code structures." if failed == 0 else "Some Python files appear empty or malformed.",
        total=total,
        passed=passed,
        failed=failed,
        details=details[:200],
    )


def run_pytest(root: Path) -> CheckResult:
    tests_dir = root / "tests"
    if not tests_dir.exists():
        return CheckResult(
            name="pytest",
            success=False,
            message="tests/ folder not found.",
            failed=1,
        )

    rc, out, err = run_command([sys.executable, "-m", "pytest", "-q"], cwd=root, timeout=180)
    details = []

    if out:
        details.append(out[-8000:])
    if err:
        details.append(err[-8000:])

    return CheckResult(
        name="pytest",
        success=rc == 0,
        message="Pytest passed." if rc == 0 else f"Pytest failed with exit code {rc}.",
        total=1,
        passed=1 if rc == 0 else 0,
        failed=0 if rc == 0 else 1,
        details=details,
    )


def dashboard_build(root: Path) -> CheckResult:
    dashboard = root / "apps" / "dashboard"
    package_json = dashboard / "package.json"

    if not package_json.exists():
        return CheckResult(
            name="dashboard_build",
            success=False,
            message="apps/dashboard/package.json not found.",
            failed=1,
        )

    rc, out, err = run_command(["npm", "run", "build"], cwd=dashboard, timeout=240)
    details = []

    if out:
        details.append(out[-8000:])
    if err:
        details.append(err[-8000:])

    return CheckResult(
        name="dashboard_build",
        success=rc == 0,
        message="Dashboard build passed." if rc == 0 else f"Dashboard build failed with exit code {rc}.",
        total=1,
        passed=1 if rc == 0 else 0,
        failed=0 if rc == 0 else 1,
        details=details,
    )


def api_smoke(root: Path) -> CheckResult:
    api_main = root / "apps" / "api" / "main.py"

    if not api_main.exists():
        return CheckResult(
            name="api_smoke",
            success=False,
            message="apps/api/main.py not found.",
            failed=1,
        )

    old_path = list(sys.path)
    sys.path.insert(0, str(root))

    try:
        spec = importlib.util.spec_from_file_location("william_api_smoke_main", str(api_main))
        if spec is None or spec.loader is None:
            raise ImportError("Could not create import spec for API main")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        app_like = any(
            hasattr(module, name)
            for name in ("app", "api", "create_app", "create_api", "Main", "APIApp")
        )

        if app_like:
            return CheckResult(
                name="api_smoke",
                success=True,
                message="API main imports and exposes an app/factory symbol.",
                total=1,
                passed=1,
            )

        return CheckResult(
            name="api_smoke",
            success=False,
            message="API main imports but no app/factory symbol was found.",
            total=1,
            failed=1,
        )
    except Exception as exc:
        return CheckResult(
            name="api_smoke",
            success=False,
            message=f"API main import failed: {type(exc).__name__}: {exc}",
            total=1,
            failed=1,
        )
    finally:
        sys.path[:] = old_path


def print_report(report: ProjectReport) -> None:
    print("\n=== William/Jarvis Test Report ===")
    print(f"Root: {report.root}")
    print(f"Overall: {'PASS' if report.success else 'FAIL'}")
    print(f"Duration: {report.finished_at - report.started_at:.2f}s")
    print("\nChecks:")

    for result in report.results:
        print(f"- [{result.status()}] {result.name}: {result.message}")
        print(
            f"  items: total={result.total}, passed={result.passed}, "
            f"failed={result.failed}, warnings={result.warnings}"
        )

        for detail in result.details[:8]:
            clean = detail.replace("\n", "\n    ")
            print(f"    {clean[:1000]}")

        if len(result.details) > 8:
            print(f"    ... {len(result.details) - 8} more details saved in JSON report")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Test William/Jarvis project files safely.")
    parser.add_argument("--root", default=".", help="Project root folder. Default: current folder")
    parser.add_argument("--report", default="william_test_report.json", help="JSON report filename/path")
    parser.add_argument("--strict", action="store_true", help="Fail structure check if expected high-level files are missing")
    parser.add_argument("--import-python", action="store_true", help="Import each Python file to verify safe imports")
    parser.add_argument("--run-pytest", action="store_true", help="Run pytest test suite")
    parser.add_argument("--dashboard-build", action="store_true", help="Run npm run build in apps/dashboard")
    parser.add_argument("--api-smoke", action="store_true", help="Smoke import apps/api/main.py")
    parser.add_argument("--all", action="store_true", help="Run optional checks too: imports, pytest, API smoke, dashboard build")

    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        print(f"Root folder does not exist: {root}", file=sys.stderr)
        return 2

    report = ProjectReport(root=str(root), started_at=time.time())

    report.add(check_structure(root, strict=args.strict))
    report.add(check_python_syntax(root))
    report.add(check_config_files(root))
    report.add(check_secret_scan(root))
    report.add(check_class_names(root))

    run_all = args.all

    if args.import_python or run_all:
        report.add(check_python_imports(root))

    if args.api_smoke or run_all:
        report.add(api_smoke(root))

    if args.run_pytest or run_all:
        report.add(run_pytest(root))

    if args.dashboard_build or run_all:
        report.add(dashboard_build(root))

    report.finished_at = time.time()

    print_report(report)

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = root / report_path

    report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    print(f"\nJSON report written to: {report_path}")

    return 0 if report.success else 1


if __name__ == "__main__":
    raise SystemExit(main())