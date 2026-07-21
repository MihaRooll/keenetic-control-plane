"""Persistence-layer errors (mutable Exception subclasses for traceback support)."""

from __future__ import annotations


class PersistenceError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConflictError(PersistenceError):
    pass


class PreconditionFailed(PersistenceError):
    pass


class IdempotencyConflict(PersistenceError):
    pass


class StaleFenceError(PersistenceError):
    pass


class NotFoundError(PersistenceError):
    pass
