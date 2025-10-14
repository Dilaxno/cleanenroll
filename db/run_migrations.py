"""
Simple migration runner for Neon using SQLAlchemy async engine.

- Applies all .sql files in backend/db/migrations/ in lexicographic order
- Each file may contain multiple statements separated by semicolons
- Statements that are empty or whitespace are skipped
- Designed for idempotent migrations (use IF NOT EXISTS where applicable)

Usage:
  python -m backend.db.run_migrations
or
  python backend/db/run_migrations.py
"""
import os
import asyncio
from pathlib import Path
from typing import List

from sqlalchemy.sql import text

# Reuse the configured async engine from database.py
try:
    # When run as a module: python -m backend.db.run_migrations
    from .database import engine
except Exception:
    # When run as a script: python backend/db/run_migrations.py
    # Add project root to sys.path and import via absolute package path
    import sys
    from pathlib import Path as _Path
    project_root = _Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from backend.db.database import engine

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _load_sql_files() -> List[Path]:
    if not MIGRATIONS_DIR.exists():
        return []
    files = [p for p in MIGRATIONS_DIR.iterdir() if p.is_file() and p.suffix.lower() == ".sql"]
    files.sort(key=lambda p: p.name)
    return files


def _split_statements(sql: str) -> List[str]:
    """Very simple SQL splitter on semicolons.
    This assumes our migrations are straightforward DDL/DML without procedural bodies.
    """
    parts = []
    buf = []
    for line in sql.splitlines():
        # Skip SQL comments that start with --
        if line.strip().startswith("--"):
            parts_line = "\n".join(buf)
            # do not flush here; comments do not impact separators
            pass
        buf.append(line)
        if ";" in line:
            joined = "\n".join(buf)
            # split on ; and keep everything before the last ; in this chunk
            chunks = joined.split(";")
            # all except the last are complete statements
            for c in chunks[:-1]:
                stmt = c.strip()
                if stmt:
                    parts.append(stmt)
            # start new buffer with remainder (after last ;)
            buf = [chunks[-1]] if chunks[-1] else []
    # leftover
    tail = "\n".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


async def apply_migration_file(path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    statements = _split_statements(sql)
    if not statements:
        print(f"[migrate] {path.name}: no statements (skipped)")
        return
    async with engine.begin() as conn:
        for stmt in statements:
            try:
                await conn.execute(text(stmt))
            except Exception as e:
                # Report but continue with next statements/files; migrations should be idempotent
                print(f"[migrate] {path.name}: error executing statement -> {e}")
                raise
    print(f"[migrate] {path.name}: applied {len(statements)} statements")


async def main() -> None:
    files = _load_sql_files()
    if not files:
        print(f"[migrate] no migration files found in {MIGRATIONS_DIR}")
        return
    print(f"[migrate] applying {len(files)} migration file(s) from {MIGRATIONS_DIR}")
    try:
        for f in files:
            await apply_migration_file(f)
        print("[migrate] done")
    finally:
        # Ensure the async engine is disposed before the event loop closes.
        # This avoids a noisy Windows asyncio SSL transport error on shutdown.
        try:
            await engine.dispose()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
