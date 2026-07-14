"""
tests/database_tests/test_db_path_resolution.py

Regression tests for database/db.py's Db._anchor_relative_sqlite_url().

Root-cause bug this guards against: the SQLite dev-fallback URL
("sqlite:///./william.db") is relative, and sqlite3 resolves a relative
path against whatever directory the CURRENT PROCESS happens to be running
from -- not against the repository. Two independently-launched processes
(a real backend server started one way, scripts/grant_platform_admin.py
run another way) could each open a different, unrelated william.db file
with no error from either side: a script could report
is_platform_admin=True while every real API request kept reading a
separate, unmodified database. _anchor_relative_sqlite_url() rewrites any
relative sqlite:/// URL to an absolute path anchored at the repo root
(database/db.py's own parent directory) before it ever reaches
SQLAlchemy/sqlite3, so this is deterministic regardless of launch-time
working directory.
"""

from __future__ import annotations

import os

from database.db import Db, REPO_ROOT


class TestAnchorRelativeSqliteUrl:
    def test_default_relative_url_resolves_to_repo_root(self) -> None:
        resolved = Db._anchor_relative_sqlite_url("sqlite:///./william.db")
        expected = f"sqlite:///{(REPO_ROOT / 'william.db').resolve().as_posix()}"
        assert resolved == expected

    def test_resolution_is_identical_regardless_of_process_cwd(self) -> None:
        """This is the exact bug: the same relative URL must resolve to
        the same absolute path no matter what directory the calling
        process happens to be in."""
        from_root = Db._anchor_relative_sqlite_url("sqlite:///./william.db")

        original_cwd = os.getcwd()
        try:
            os.chdir(str(REPO_ROOT / "apps"))
            from_apps_dir = Db._anchor_relative_sqlite_url("sqlite:///./william.db")
        finally:
            os.chdir(original_cwd)

        assert from_root == from_apps_dir

    def test_relative_url_without_dot_slash_also_anchored(self) -> None:
        resolved = Db._anchor_relative_sqlite_url("sqlite:///william.db")
        expected = f"sqlite:///{(REPO_ROOT / 'william.db').resolve().as_posix()}"
        assert resolved == expected

    def test_relative_url_with_subdirectory_is_anchored_under_repo_root(self) -> None:
        resolved = Db._anchor_relative_sqlite_url("sqlite:///./storage/dev.db")
        expected = f"sqlite:///{(REPO_ROOT / 'storage' / 'dev.db').resolve().as_posix()}"
        assert resolved == expected

    def test_absolute_unix_style_sqlite_url_passes_through_unchanged(self) -> None:
        url = "sqlite:////absolute/unix/path/william.db"
        assert Db._anchor_relative_sqlite_url(url) == url

    def test_windows_drive_absolute_sqlite_url_passes_through_unchanged(self) -> None:
        url = "sqlite:///C:/some/absolute/path/william.db"
        assert Db._anchor_relative_sqlite_url(url) == url

    def test_in_memory_sqlite_url_passes_through_unchanged(self) -> None:
        url = "sqlite:///:memory:"
        assert Db._anchor_relative_sqlite_url(url) == url

    def test_non_sqlite_url_passes_through_unchanged(self) -> None:
        url = "postgresql://user:pass@localhost:5432/william"
        assert Db._anchor_relative_sqlite_url(url) == url

    def test_db_manager_singleton_uses_an_absolute_sqlite_path(self) -> None:
        """The real module-level db_manager (used by every route/script)
        must never carry a bare relative sqlite path once resolved."""
        from database.db import db_manager

        if db_manager.engine.dialect.name != "sqlite":
            return  # test environment/deployment uses a non-sqlite DB

        rendered = db_manager.engine.url.render_as_string(hide_password=True)
        if ":memory:" in rendered:
            return  # pytest's own in-memory test database

        # SQLAlchemy's sqlite URL rendering always includes an absolute
        # path once resolved -- on POSIX that's a leading "/", on Windows
        # it's a drive letter.
        raw_path = rendered[len("sqlite:///"):]
        assert raw_path.startswith("/") or (len(raw_path) > 1 and raw_path[1] == ":")
