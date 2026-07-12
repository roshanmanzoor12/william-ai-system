"""
scripts/reset_dev_db.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Safe, explicit dev-database reset helper.

This script does exactly one thing: delete the local SQLite dev database
file (default `william.db`, repo root) plus its `-journal`/`-shm`/`-wal`
sidecar files, so the next backend boot creates a brand-new, empty schema
(see apps/api/main.py::Main._initialize_database(), which imports every
model and calls Base.metadata.create_all() automatically for SQLite dev
databases).

It NEVER runs automatically -- nothing in this codebase imports or calls
this script. It only deletes anything when a human runs it directly AND
passes --yes; without that flag it only prints what it *would* delete.

Usage:
    python scripts/reset_dev_db.py            # dry run -- lists files, deletes nothing
    python scripts/reset_dev_db.py --yes       # actually deletes them

Manual reset steps this script automates (do these by hand if you'd rather
not run a script):
    1. Stop the backend (Ctrl+C, or stop the uvicorn/python process).
    2. Delete william.db, william.db-journal, william.db-shm, william.db-wal
       from the repo root.
    3. Restart the backend:
       python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
    4. Register a user again -- the previous database (including any
       registered users) is gone; there is no user data left to log into.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEV_DB_FILES = (
    "william.db",
    "william.db-journal",
    "william.db-shm",
    "william.db-wal",
)


def resolve_db_basename() -> str:
    """Mirrors database/db.py::Db.DEFAULT_SQLITE_URL / DATABASE_URL so this
    script targets the same file the backend actually uses, not a hardcoded
    guess -- if DATABASE_URL points elsewhere, say so instead of silently
    deleting the wrong file."""
    url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "sqlite:///./william.db"
    if not url.startswith("sqlite"):
        return ""
    return Path(url.split("///")[-1]).name


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Delete the local SQLite dev database so the next backend boot starts clean.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete the files. Without this flag, only a dry-run listing is printed.",
    )
    args = parser.parse_args(argv)

    configured_name = resolve_db_basename()
    if configured_name and configured_name != "william.db":
        print(
            f"DATABASE_URL points at a SQLite file named {configured_name!r}, not william.db. "
            "This script only ever touches the four default william.db* filenames listed below "
            "-- delete the configured file yourself if that's what you intend to reset."
        )

    targets = [REPO_ROOT / name for name in DEV_DB_FILES]
    existing = [p for p in targets if p.exists()]

    if not existing:
        print("No william.db / sidecar files found -- nothing to reset.")
        print("Start the backend and it will create a fresh database automatically:")
        print("  python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload")
        return 0

    print("This will permanently delete all local dev data (users, workspaces, tasks, voice settings, everything):")
    for path in existing:
        print(f"  - {path}")

    if not args.yes:
        print("\nDry run only -- nothing was deleted. Re-run with --yes to actually delete these files.")
        return 0

    for path in existing:
        path.unlink()
        print(f"Deleted {path}")

    print("\nDone. Next steps:")
    print("  1. Start the backend (it will create a fresh, empty schema automatically):")
    print("     python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload")
    print("  2. Register a user again -- the previous database had no surviving data:")
    print('     curl -X POST http://localhost:8000/api/v1/auth/register -H "Content-Type: application/json" \\')
    print('       -d \'{"email":"owner@example.com","password":"TestPass123","full_name":"Owner","workspace_name":"My Workspace"}\'')
    return 0


if __name__ == "__main__":
    sys.exit(main())
