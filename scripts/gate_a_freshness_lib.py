"""Pure helpers for automated same-tuple Gate A freshness recertification.

Fail-closed by construction: apply_recertification() only ever mutates the
certification mapping when the newly probed tuple is byte-identical to the
currently certified tuple (via GateACertification.matches_probe_evidence).
Any drift, or a probe that is not certification_eligible/identity_complete,
must leave the certification mapping completely untouched.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "docs" / "gate-a-certification.json"
DEFAULT_ARTIFACT_DIR = REPO_ROOT / "data" / "artifacts"
DEFAULT_AUTOMATION_LOG_PATH = DEFAULT_ARTIFACT_DIR / "gate-a-recert-automation.log"
DEFAULT_HOST = "192.168.2.1"
DEFAULT_USERNAME = "admin"
DEFAULT_CREDENTIAL_REF = "cred_69280efb9361ca2911e99d383f0ce474"
DEFAULT_SSH_HOST_KEY_SHA256 = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
DEFAULT_SOURCE_ADDRESS = "192.168.2.10"
DEFAULT_REFRESH_MARGIN_HOURS = 12.0


class GateAFreshnessError(Exception):
    """Probe subprocess failure, malformed artifact, or config load error."""


@dataclass(frozen=True)
class RecertificationOutcome:
    status: Literal["recertified", "drift_detected", "not_due", "ineligible"]
    message: str
    diffs: tuple[str, ...] = ()
    deadline: datetime | None = None
    proactive: bool | None = None


def _parse_iso_datetime(value: str) -> datetime:
    text = value.strip()
    if not text:
        raise GateAFreshnessError("evidence_recorded_at is required")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _normalize_pin(value: str) -> str:
    stripped = value.strip()
    if stripped.upper().startswith("SHA256:"):
        return f"SHA256:{stripped.split(':', 1)[1].strip()}"
    return f"SHA256:{stripped}" if stripped else ""


def load_raw_config(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        raise GateAFreshnessError(f"Gate A config not found: {config_path}")
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateAFreshnessError(f"malformed Gate A config JSON: {config_path}") from exc
    if not isinstance(payload, dict):
        raise GateAFreshnessError(f"Gate A config must be an object: {config_path}")
    return payload


def compute_deadline(raw_config: dict[str, Any]) -> datetime:
    recorded_at = _parse_iso_datetime(str(raw_config["evidence_recorded_at"]))
    hours = float(raw_config.get("opening_freshness_hours", 24))
    return recorded_at + timedelta(hours=hours)


def is_due(
    raw_config: dict[str, Any],
    *,
    now: datetime,
    margin_hours: float = DEFAULT_REFRESH_MARGIN_HOURS,
) -> bool:
    deadline = compute_deadline(raw_config)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now = now.astimezone(UTC)
    return now >= deadline - timedelta(hours=margin_hours)


def _config_value(raw_config: dict[str, Any], key: str) -> Any:
    return raw_config.get(key)


def _evidence_value(evidence: dict[str, Any], key: str, *aliases: str) -> Any:
    if key in evidence:
        return evidence.get(key)
    for alias in aliases:
        if alias in evidence:
            return evidence.get(alias)
    return None


def diff_tuple_fields(raw_config: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    diffs: list[str] = []

    direct_pairs = [
        "model",
        "firmware_version",
        "region",
        "update_channel",
        "component_set_digest",
        "certification_eligible",
        "ssh_host_key_algorithm",
    ]
    for key in direct_pairs:
        config_val = _config_value(raw_config, key)
        evidence_val = evidence.get(key)
        if config_val != evidence_val:
            diffs.append(key)

    if "identity_complete" in raw_config:
        if raw_config.get("identity_complete") != evidence.get("identity_complete"):
            diffs.append("identity_complete")

    config_ndm = _config_value(raw_config, "ndm_build")
    evidence_ndm = _evidence_value(evidence, "ndm_build", "build")
    if config_ndm != evidence_ndm:
        diffs.append("ndm_build")

    config_fp = _config_value(raw_config, "device_fingerprint_digest")
    evidence_fp = _evidence_value(evidence, "device_fingerprint_digest", "device_fingerprint")
    if config_fp != evidence_fp:
        diffs.append("device_fingerprint_digest")

    config_transport = _config_value(raw_config, "transport")
    evidence_transport = _evidence_value(evidence, "transport", "transport_security")
    if config_transport != evidence_transport:
        diffs.append("transport")

    config_pin = _normalize_pin(
        str(_config_value(raw_config, "ssh_host_key_fingerprint_sha256") or "")
    )
    evidence_pin = _normalize_pin(
        str(evidence.get("ssh_host_key_fingerprint_sha256") or "")
    )
    if config_pin != evidence_pin:
        diffs.append("ssh_host_key_fingerprint_sha256")

    return diffs


def evaluate_and_apply(
    raw_config: dict[str, Any],
    *,
    evidence: dict[str, Any],
    evidence_path_rel: str,
    evidence_sha256: str,
    now: datetime,
    automation_label: str = "automated",
) -> tuple[RecertificationOutcome, dict[str, Any]]:
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now = now.astimezone(UTC)

    diffs = diff_tuple_fields(raw_config, evidence)
    eligible = evidence.get("certification_eligible") is True
    identity_complete = evidence.get("identity_complete") is True

    if diffs or not eligible or not identity_complete:
        if diffs:
            status: Literal["drift_detected", "ineligible"] = "drift_detected"
            message = (
                f"Gate A tuple drift detected ({len(diffs)} field(s) differ: "
                f"{', '.join(diffs)}). Certification file left unchanged."
            )
        else:
            status = "ineligible"
            reasons: list[str] = []
            if not eligible:
                reasons.append("certification_eligible=false")
            if not identity_complete:
                reasons.append("identity_complete=false")
            message = (
                f"Probe evidence ineligible ({', '.join(reasons)}). "
                "Certification file left unchanged."
            )
        return (
            RecertificationOutcome(status=status, message=message, diffs=tuple(diffs)),
            raw_config,
        )

    old_evidence_recorded_at = raw_config["evidence_recorded_at"]
    old_deadline = compute_deadline(raw_config)
    old_evidence_path = raw_config["evidence_path"]
    proactive = now < old_deadline

    date_suffix = now.strftime("%Y%m%d")
    superseded_on = _parse_iso_datetime(str(old_evidence_recorded_at)).date().isoformat()
    recertified_on = now.date().isoformat()
    supersession_reason = (
        f"evidence_freshness_recertification_same_tuple_{automation_label}_{date_suffix}"
    )

    proactive_label = "proactive" if proactive else "reactive"
    superseded_entry: dict[str, Any] = {
        "status": "superseded_evidence",
        "superseded_on": superseded_on,
        "supersession_reason": supersession_reason,
        "component_set_digest": raw_config["component_set_digest"],
        "device_fingerprint_digest": raw_config["device_fingerprint_digest"],
        "ssh_host_key_fingerprint_sha256": raw_config["ssh_host_key_fingerprint_sha256"],
        "evidence_recorded_at": old_evidence_recorded_at,
        "evidence_sha256": raw_config["evidence_sha256"],
        "evidence_path": raw_config["evidence_path"],
        "source_address": raw_config.get("source_address"),
        "note": (
            f"Same tuple, freshness-only automated recertification ({proactive_label}). "
            "Certified tuple UNCHANGED byte-for-byte. drifted_fields=0."
        ),
    }

    new_config = deepcopy(raw_config)
    previous = list(new_config.get("previous_certifications") or [])
    previous.append(superseded_entry)
    new_config["previous_certifications"] = previous
    new_config["recertified_on"] = recertified_on
    new_config["recertification_reason"] = supersession_reason
    new_config["recertification_note"] = (
        f"Automated same-tuple freshness-only refresh ({proactive_label}). "
        "Certified tuple UNCHANGED byte-for-byte (drifted_fields=0). "
        f"identity_complete=true, certification_eligible=true. "
        f"Evidence pointer updated: {old_evidence_path} -> {evidence_path_rel}."
    )
    new_config["evidence_recorded_at"] = evidence["evidence_recorded_at"]
    new_config["evidence_sha256"] = evidence_sha256.lower().removeprefix("sha256:")
    new_config["evidence_path"] = evidence_path_rel

    new_deadline = compute_deadline(new_config)
    message = (
        f"Gate A freshness recertified ({proactive_label}): "
        f"{old_evidence_path} -> {evidence_path_rel}. "
        f"New opening deadline: {new_deadline.isoformat()}."
    )
    return (
        RecertificationOutcome(
            status="recertified",
            message=message,
            deadline=new_deadline,
            proactive=proactive,
        ),
        new_config,
    )


def write_config(config_path: Path, raw_config: dict[str, Any]) -> None:
    config_path.write_text(
        json.dumps(raw_config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def run_probe(
    *,
    host: str,
    username: str,
    credential_ref: str,
    ssh_host_key_sha256: str,
    source_address: str,
    artifact_out: Path,
    secrets_root: Path | None = None,
    python_executable: str | None = None,
) -> Path:
    cmd = [
        python_executable or sys.executable,
        str(REPO_ROOT / "scripts" / "probe-gate-a.py"),
        "--host",
        host,
        "--credential-ref",
        credential_ref,
        "--username",
        username,
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        ssh_host_key_sha256,
        "--source-address",
        source_address,
        "--artifact-out",
        str(artifact_out),
    ]
    if secrets_root is not None:
        cmd.extend(["--secrets-root", str(secrets_root)])

    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise GateAFreshnessError(
            f"probe-gate-a.py failed (exit {result.returncode}): {stderr}"
        )
    return artifact_out


def load_evidence(artifact_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateAFreshnessError(f"malformed evidence JSON: {artifact_path}") from exc
    if not isinstance(payload, dict):
        raise GateAFreshnessError(f"evidence artifact must be an object: {artifact_path}")
    return payload


def sha256_of_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def append_log(log_path: Path, line: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).isoformat()
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"{timestamp} {line}\n")
