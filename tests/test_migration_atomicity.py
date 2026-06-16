"""Storage-layer tests: migration atomicity.

A failing migration file must roll back both the schema change AND the
bookkeeping row, so a subsequent startup retries the migration. Otherwise
the DB could be left in a half-applied state forever.
"""
import sqlite3
from pathlib import Path as RealPath

import pytest

from rgt_vault.storage.sqlite import StorageBackend


class _PathProxy:
    """Path stand-in that returns a fake dir when the suffix is 'migrations'."""
    def __init__(self, real, override=None):
        # ``real`` is the underlying RealPath used for OS calls (fspath,
        # chmod, sqlite3.connect). ``override`` is the dir we WANT the
        # caller to see for path listing/reading.
        self._real = real
        self._override = override

    def __truediv__(self, other):
        # When the caller does Path(__file__).parent / "migrations", we
        # build a new proxy pointing at our override dir.
        if str(other) == "migrations":
            return _PathProxy(self._real, override=self._override)
        return _PathProxy(self._real / other, override=self._override)

    @property
    def parent(self):
        return _PathProxy(self._real.parent, override=self._override)

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if self._override is not None and name in ("glob", "exists", "iterdir", "read_text"):
            target = RealPath(self._override)
            if callable(attr):
                def call(*args, **kwargs):
                    return getattr(target, name)(*args, **kwargs)
                return call
            return attr
        return attr

    def __str__(self):
        return str(self._override if self._override is not None else self._real)

    def __fspath__(self):
        return str(self._real)


def test_failed_migration_rolls_back_bookkeeping(tmp_path, monkeypatch):
    """Inject a fake migration directory containing a real no-op migration
    (9998) and a failing one (9999). The test verifies that 9999 is NOT
    recorded in ``schema_migrations`` (its script errored and the
    transaction rolled back) while 9998 IS recorded.
    """
    db_path = tmp_path / "vault.db"

    fake_dir = tmp_path / "fake_migrations"
    fake_dir.mkdir()
    (fake_dir / "9998_noop.sql").write_text("CREATE TABLE IF NOT EXISTS _mig_9998 (x INTEGER);")
    (fake_dir / "9999_bad.sql").write_text("INSERT INTO no_such_table_for_real VALUES (1);")

    def _path_factory(arg="."):
        s = str(arg)
        # The storage code does: migrations_dir = Path(__file__).parent / "migrations"
        # Substitute the override dir when the call site is the storage module.
        if s.endswith("sqlite.py"):
            return _PathProxy(RealPath(arg), override=fake_dir)
        return _PathProxy(RealPath(arg))

    import rgt_vault.storage.sqlite as sqlite_mod
    monkeypatch.setattr(sqlite_mod, "Path", _path_factory)

    with pytest.raises(sqlite3.OperationalError):
        StorageBackend(str(db_path))

    conn = sqlite3.connect(str(db_path))
    try:
        versions = [v for (v,) in conn.execute("SELECT version FROM schema_migrations").fetchall()]
    finally:
        conn.close()
    # 9999 failed; it must NOT be recorded.
    assert 9999 not in versions, f"Failed migration 9999 was recorded: {versions}"
    # 9998 was a real no-op; it must be recorded.
    assert 9998 in versions
