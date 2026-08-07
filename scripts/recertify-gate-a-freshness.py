#!/usr/bin/env python3
"""CLI orchestrator for automated same-tuple Gate A freshness recertification."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from gate_a_freshness_lib import (
    DEFAULT_ARTIFACT_DIR,
    DEFAULT_AUTOMATION_LOG_PATH,
    DEFAULT_CONFIG_PATH,
    DEFAULT_CREDENTIAL_REF,
    DEFAULT_HOST,
    DEFAULT_REFRESH_MARGIN_HOURS,
    DEFAULT_SOURCE_ADDRESS,
    DEFAULT_SSH_HOST_KEY_SHA256,
    DEFAULT_USERNAME,
    REPO_ROOT,
    GateAFreshnessError,
    append_log,
    compute_deadline,
    evaluate_and_apply,
    is_due,
    load_evidence,
    load_raw_config,
    run_probe,
    sha256_of_file,
    write_config,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Automated same-tuple Gate A freshness recertification "
            "(fail-closed on any tuple drift)."
        )
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--credential-ref", default=DEFAULT_CREDENTIAL_REF)
    parser.add_argument("--ssh-host-key-sha256", default=DEFAULT_SSH_HOST_KEY_SHA256)
    parser.add_argument("--source-address", default=DEFAULT_SOURCE_ADDRESS)
    parser.add_argument("--secrets-root", default=None)
    parser.add_argument("--config-path", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--refresh-margin-hours",
        type=float,
        default=DEFAULT_REFRESH_MARGIN_HOURS,
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--python-executable", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    log_path = DEFAULT_AUTOMATION_LOG_PATH

    try:
        raw_config = load_raw_config(args.config_path)
    except GateAFreshnessError as exc:
        print(str(exc), file=sys.stderr)
        return 4

    now = datetime.now(UTC)

    if not args.force and not is_due(
        raw_config,
        now=now,
        margin_hours=args.refresh_margin_hours,
    ):
        deadline = compute_deadline(raw_config)
        print(
            f"Gate A freshness not yet due (deadline={deadline.isoformat()}); nothing to do."
        )
        append_log(log_path, "not_due")
        return 0

    artifact_out = DEFAULT_ARTIFACT_DIR / f"gate-a-probe-auto-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    artifact_out.parent.mkdir(parents=True, exist_ok=True)

    secrets_root = Path(args.secrets_root) if args.secrets_root else None

    try:
        run_probe(
            host=args.host,
            username=args.username,
            credential_ref=args.credential_ref,
            ssh_host_key_sha256=args.ssh_host_key_sha256,
            source_address=args.source_address,
            artifact_out=artifact_out,
            secrets_root=secrets_root,
            python_executable=args.python_executable,
        )
    except GateAFreshnessError as exc:
        print(str(exc), file=sys.stderr)
        append_log(log_path, f"probe_failed: {exc}")
        return 2

    evidence = load_evidence(artifact_out)
    evidence_sha256 = sha256_of_file(artifact_out)
    evidence_path_rel = artifact_out.relative_to(REPO_ROOT).as_posix()

    outcome, new_config = evaluate_and_apply(
        raw_config,
        evidence=evidence,
        evidence_path_rel=evidence_path_rel,
        evidence_sha256=evidence_sha256,
        now=now,
    )

    print(outcome.message)

    if outcome.status == "recertified":
        if not args.dry_run:
            write_config(args.config_path, new_config)
            print(
                f"Updated {args.config_path}: evidence_path={evidence_path_rel}, "
                f"deadline={outcome.deadline.isoformat() if outcome.deadline else 'unknown'}"
            )
        append_log(
            log_path,
            f"recertified proactive={outcome.proactive} evidence_path={evidence_path_rel}",
        )
        return 0

    if outcome.diffs:
        print(f"Drifted fields: {', '.join(outcome.diffs)}", file=sys.stderr)
    append_log(log_path, f"{outcome.status}: {','.join(outcome.diffs)}")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
