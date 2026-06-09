"""Database engine and session management.

The whole product talks to Postgres through SQLAlchemy 2.0's ORM. This module
owns the single shared ``Engine`` and the ``Session`` factory; everything else
(repositories, the worker, the API) imports ``session_scope`` or ``SessionLocal``
from here rather than constructing engines of their own.

The legacy ``redhive.db`` core-SQL helpers are kept for backward compatibility
but new code should use the ORM models in ``redhive.db_models`` via these
sessions.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from redhive.config import settings


def _make_engine() -> Engine:
    """Build the shared engine.

    ``pool_pre_ping`` recycles dead connections so a restarted Postgres
    container does not poison the pool. ``pool_size``/``max_overflow`` are sized
    for an API process plus a handful of worker threads.
    """
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        future=True,
    )


engine: Engine = _make_engine()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional session scope.

    Commits on success, rolls back on any exception, and always closes. Use for
    a unit of work::

        with session_scope() as db:
            db.add(obj)
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
