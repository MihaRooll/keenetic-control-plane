"""Opaque immutable identifier value objects."""

from __future__ import annotations

from dataclasses import dataclass


def _validate_non_empty(value: str, name: str) -> str:
    if not value or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class RouterId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "RouterId"))


@dataclass(frozen=True, slots=True)
class ObservationId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "ObservationId"))


@dataclass(frozen=True, slots=True)
class CapabilityId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "CapabilityId"))


@dataclass(frozen=True, slots=True)
class RevisionId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "RevisionId"))


@dataclass(frozen=True, slots=True)
class ResourceId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "ResourceId"))


@dataclass(frozen=True, slots=True)
class PlanId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "PlanId"))


@dataclass(frozen=True, slots=True)
class OperationId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "OperationId"))


@dataclass(frozen=True, slots=True)
class ArtifactId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "ArtifactId"))


@dataclass(frozen=True, slots=True)
class StepId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _validate_non_empty(self.value, "StepId"))
