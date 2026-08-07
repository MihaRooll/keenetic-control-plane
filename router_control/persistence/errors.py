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


class FenceExpiredError(PersistenceError):
    pass


class MutexHolderRequiredError(PersistenceError):
    pass


class RecoveryConflictError(PersistenceError):
    pass


class EffectTransitionError(PersistenceError):
    pass


class UnknownBootError(PersistenceError):
    pass


class ArtifactNotRestorableError(PersistenceError):
    pass


class SealedApplyTrailBeginError(PersistenceError):
    """Sealed apply trail row could not be created; device dispatch must not proceed."""
