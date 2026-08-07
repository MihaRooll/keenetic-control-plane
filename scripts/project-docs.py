"""Project documentation lifecycle CLI (stdlib only): audit, sync-marker, impact."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

VALID_STATUSES = frozenset({"active", "draft", "deprecated", "planned"})
MAP_REL = Path("docs") / "docs-map.json"
STATE_REL = Path("docs") / "project-state.md"
STATUS_REL = Path("docs") / "STATUS.yaml"
MARKER_RE = re.compile(
    r"<!--\s*project-docs-sync:\s*phase=(?P<phase>\S+)\s+updated=(?P<updated>\S+)\s*-->"
)
INLINE_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(([^)]+)\)")
REF_DEF_RE = re.compile(r"^\s*\[([^\]]+)\]:\s*(\S+)", re.MULTILINE)
REF_USE_RE = re.compile(r"(?<!!)\[([^\]]+)\]\[([^\]]*)\]")

# Curated unmapped ignores (repo-relative glob-like prefixes/patterns).
UNMAPPED_IGNORE_PREFIXES = (
    ".cursor/",
    "data/",
    "templates/",  # toolkit scaffolding copies; not living project docs
    "tests/project-docs/fixtures/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".git/",
)
UNMAPPED_IGNORE_EXACT = frozenset(
    {
        "docs/papercuts.md",
    }
)

PROJECT_DOCS_SCRIPTS = (
    "scripts/project-docs.py",
    "scripts/project-docs.ps1",
    "scripts/validate-project-docs.ps1",
)


@dataclass
class Finding:
    category: str
    message: str
    severity: str = "error"


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.findings)


class ProjectRoot:
    def __init__(self, root: Path) -> None:
        resolved = root.resolve()
        if not resolved.is_dir():
            raise ValueError(f"project root is not a directory: {root}")
        self.root = resolved

    def rel(self, path: Path | str) -> str:
        candidate = Path(path)
        if candidate.is_absolute():
            full = candidate.resolve()
        else:
            full = (self.root / candidate).resolve()
        try:
            rel = full.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"path escapes project root: {path}") from exc
        return rel.as_posix()

    def resolve_under(
        self,
        rel_path: str,
        *,
        base: Path | None = None,
        allow_parent: bool = False,
    ) -> Path:
        if not rel_path or rel_path.strip() == "":
            raise ValueError("empty path")
        normalized = rel_path.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[a-zA-Z]:", normalized):
            raise ValueError(f"absolute path not allowed: {rel_path}")
        if not allow_parent and ".." in Path(normalized).parts:
            raise ValueError(f"path must not contain ..: {rel_path}")
        anchor = base if base is not None else self.root
        full = (anchor / Path(normalized)).resolve()
        try:
            full.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"path escapes project root: {rel_path}") from exc
        return full

    def is_under(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.root)
            return True
        except ValueError:
            return False


def _strip_bom(text: str) -> str:
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def read_text(path: Path) -> str:
    return _strip_bom(path.read_text(encoding="utf-8"))


def parse_status_yaml(status_path: Path) -> tuple[str, str]:
    if not status_path.is_file():
        raise FileNotFoundError(f"missing STATUS: {status_path}")
    text = read_text(status_path)
    updated = ""
    for line in text.splitlines():
        m = re.match(r'^updated:\s*"(.*)"\s*$', line.strip())
        if m:
            updated = m.group(1)
            break
        m2 = re.match(r"^updated:\s*(\S+)\s*$", line.strip())
        if m2:
            updated = m2.group(1).strip("'\"")
            break

    phase_id = ""
    in_current = False
    for line in text.splitlines():
        stripped = line.rstrip()
        if re.match(r"^current_phase:\s*$", stripped):
            in_current = True
            continue
        if in_current:
            if stripped and not stripped.startswith(" ") and not stripped.startswith("\t"):
                if phase_id:
                    break
                in_current = False
                continue
            m = re.match(r'^\s+id:\s*"(.*)"\s*$', stripped)
            if m:
                phase_id = m.group(1)
                break
            m2 = re.match(r"^\s+id:\s*(\S+)\s*$", stripped)
            if m2:
                phase_id = m2.group(1).strip("'\"")
                break

    if not phase_id:
        raise ValueError("current_phase.id not found in STATUS.yaml")
    if not updated:
        raise ValueError("updated not found in STATUS.yaml")
    return phase_id, updated


def format_marker(phase_id: str, updated: str) -> str:
    return f"<!-- project-docs-sync: phase={phase_id} updated={updated} -->"


def parse_marker(text: str) -> tuple[str, str] | None:
    match = MARKER_RE.search(text)
    if not match:
        return None
    return match.group("phase"), match.group("updated")


def check_sync_marker(project: ProjectRoot, result: AuditResult) -> None:
    state_path = project.root / STATE_REL
    status_path = project.root / STATUS_REL
    if not state_path.is_file():
        result.findings.append(
            Finding("sync-marker", f"missing {STATE_REL.as_posix()}")
        )
        return
    try:
        expected_phase, expected_updated = parse_status_yaml(status_path)
    except (FileNotFoundError, ValueError) as exc:
        result.findings.append(Finding("sync-marker", str(exc)))
        return
    parsed = parse_marker(read_text(state_path))
    if parsed is None:
        result.findings.append(
            Finding(
                "sync-marker",
                "missing or malformed project-docs-sync marker in docs/project-state.md",
            )
        )
        return
    phase, updated = parsed
    if phase != expected_phase or updated != expected_updated:
        result.findings.append(
            Finding(
                "sync-marker",
                "stale project-docs-sync marker "
                f"(have phase={phase} updated={updated}, "
                f"expected phase={expected_phase} updated={expected_updated})",
            )
        )


def write_sync_marker(project: ProjectRoot) -> int:
    try:
        state_path = project.resolve_under(STATE_REL.as_posix())
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    if not project.is_under(state_path):
        print(
            f"FAIL path escapes project root: {STATE_REL.as_posix()}",
            file=sys.stderr,
        )
        return 1
    write_parent = state_path.parent
    if not project.is_under(write_parent):
        print(
            f"FAIL docs directory escapes project root: {write_parent}",
            file=sys.stderr,
        )
        return 1
    status_path = project.root / STATUS_REL
    phase_id, updated = parse_status_yaml(status_path)
    marker = format_marker(phase_id, updated)
    if state_path.is_file():
        content = read_text(state_path)
    else:
        content = ""
    if MARKER_RE.search(content):
        new_content = MARKER_RE.sub(marker, content, count=1)
    else:
        insert_after = "**SSOT:**"
        if insert_after in content:
            idx = content.index(insert_after)
            line_end = content.find("\n", idx)
            if line_end == -1:
                line_end = len(content)
            new_content = content[: line_end + 1] + "\n" + marker + "\n" + content[line_end + 1 :]
        else:
            new_content = marker + "\n\n" + content
    if not project.is_under(state_path):
        print(
            f"FAIL path escapes project root: {STATE_REL.as_posix()}",
            file=sys.stderr,
        )
        return 1
    fd, tmp_name = tempfile.mkstemp(
        dir=str(write_parent),
        prefix=".project-state-",
        suffix=".tmp",
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        if not project.is_under(tmp_path):
            print(
                f"FAIL temp file escapes project root: {tmp_path}",
                file=sys.stderr,
            )
            return 1
        tmp_path.write_text(new_content, encoding="utf-8", newline="\n")
        os.replace(tmp_path, state_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    print(f"OK  sync-marker written to {STATE_REL.as_posix()}")
    return 0


def cmd_sync_marker(project: ProjectRoot, write: bool) -> int:
    if write:
        return write_sync_marker(project)
    state_path = project.root / STATE_REL
    status_path = project.root / STATUS_REL
    phase_id, updated = parse_status_yaml(status_path)
    expected = format_marker(phase_id, updated)
    if not state_path.is_file():
        print(f"FAIL missing {STATE_REL.as_posix()}")
        return 1
    parsed = parse_marker(read_text(state_path))
    if parsed is None:
        print("FAIL missing or malformed project-docs-sync marker")
        return 1
    have = format_marker(*parsed)
    if have != expected:
        print(f"FAIL stale marker (expected {expected})")
        return 1
    print("OK  sync-marker matches STATUS.yaml")
    return 0


def _is_absolute_entry_path(path: str) -> bool:
    if not path or path.isspace():
        return False
    if re.match(r"^[a-zA-Z]:", path):
        return True
    if path.startswith("\\\\") or path.startswith("/"):
        return True
    return False


def _validate_entry(entry: Any, index: int, map_rel: str) -> dict[str, str] | None:
    label = f"entry[{index}]"
    if not isinstance(entry, dict):
        return None
    path = entry.get("path")
    title = entry.get("title")
    status = entry.get("status")
    owners = entry.get("owners")
    tags = entry.get("tags")

    if not isinstance(path, str) or not path.strip():
        return {"error": f"{label}.path required ({map_rel})"}
    if _is_absolute_entry_path(path):
        return {"error": f"{label}.path must be relative ({map_rel})"}
    if ".." in Path(path.replace("\\", "/")).parts:
        return {"error": f"{label}.path must not contain .. ({map_rel})"}
    if not isinstance(title, str) or not title.strip():
        return {"error": f"{label}.title required ({map_rel})"}
    if len(title) > 120:
        return {"error": f"{label}.title too long ({map_rel})"}
    if not isinstance(status, str) or status not in VALID_STATUSES:
        return {"error": f"{label}.status invalid: {status} ({map_rel})"}
    if not isinstance(owners, list) or len(owners) < 1:
        return {"error": f"{label}.owners requires at least one ({map_rel})"}
    for owner in owners:
        if not isinstance(owner, str) or not owner.strip():
            return {"error": f"{label}.owners contains empty value ({map_rel})"}
        if len(owner) > 64:
            return {"error": f"{label}.owners value too long ({map_rel})"}
    if tags is not None:
        if not isinstance(tags, list):
            return {"error": f"{label}.tags must be array ({map_rel})"}
        for tag in tags:
            if not isinstance(tag, str) or not tag.strip():
                return {"error": f"{label}.tags contains empty value ({map_rel})"}
            if len(tag) > 32:
                return {"error": f"{label}.tags value too long ({map_rel})"}
    return {"path": path.replace("\\", "/"), "status": status}


def validate_docs_map(project: ProjectRoot, map_rel: str = MAP_REL.as_posix()) -> list[str]:
    errors: list[str] = []
    map_path = project.root / map_rel.replace("/", os.sep)
    if not map_path.is_file():
        return [f"missing map: {map_rel}"]

    try:
        raw = read_text(map_path)
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [f"JSON parse failed: {map_rel} - {exc.msg}"]
    except OSError as exc:
        return [f"read failed: {map_rel} - {exc}"]

    if not isinstance(obj, dict):
        return [f"map root must be object ({map_rel})"]

    version = obj.get("version")
    if version is None:
        errors.append(f"version required ({map_rel})")
    elif int(version) != 1:
        errors.append(f"version must be 1 ({map_rel})")

    entries = obj.get("entries")
    if entries is None:
        errors.append(f"entries array required ({map_rel})")
        return errors
    if not isinstance(entries, list):
        errors.append(f"entries must be array ({map_rel})")
        return errors

    seen: set[str] = set()
    for idx, entry in enumerate(entries):
        info = _validate_entry(entry, idx, map_rel)
        if info is None:
            errors.append(f"entry[{idx}] is null ({map_rel})")
            continue
        if "error" in info:
            errors.append(info["error"])
            continue
        rel_path = info["path"]
        estatus = info["status"]
        if rel_path in seen:
            errors.append(f"duplicate path: {rel_path} ({map_rel})")
            continue
        seen.add(rel_path)
        try:
            candidate = project.resolve_under(rel_path)
        except ValueError as exc:
            errors.append(f"{exc} ({map_rel})")
            continue
        exists = candidate.exists()
        if estatus == "planned":
            if exists:
                errors.append(
                    f"planned entry path already exists; promote to active: {rel_path} ({map_rel})"
                )
        elif not exists:
            errors.append(f"referenced path missing: {rel_path} ({map_rel})")
        elif not project.is_under(candidate):
            errors.append(f"entry.path escapes project root: {rel_path} ({map_rel})")

    rules = obj.get("rules")
    if isinstance(rules, dict):
        for key in ("update_on_change", "validate_on_commit"):
            if key in rules and rules[key] is not None:
                val = rules[key]
                if not isinstance(val, bool):
                    s = str(val)
                    if s not in {"True", "False", "true", "false"}:
                        errors.append(f"rules.{key} must be boolean ({map_rel})")
    return errors


INLINE_CODE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")


def _strip_inline_code(text: str) -> str:
    return INLINE_CODE_RE.sub(lambda match: " " * len(match.group(0)), text)


def _normalize_link_destination(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")].strip()
    target = re.sub(r'\s+["\'][^"\']*["\']\s*$', "", target)
    return target.strip()


def _strip_code_fences(text: str) -> str:
    parts = re.split(r"^(```+|~~~+).*$", text, flags=re.MULTILINE)
    out: list[str] = []
    in_fence = False
    for part in parts:
        if re.match(r"^(```+|~~~+)$", part):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(part)
    return "".join(out)


def _is_external_link(target: str) -> bool:
    t = target.strip()
    if not t or t.startswith("#"):
        return True
    lower = t.lower()
    if lower.startswith(("http://", "https://", "mailto:", "ftp://", "data:")):
        return True
    if lower.startswith("//"):
        return True
    return False


def _iter_markdown_links(text: str) -> Iterator[tuple[str, int]]:
    body = _strip_inline_code(_strip_code_fences(text))
    ref_map: dict[str, str] = {}
    for match in REF_DEF_RE.finditer(body):
        ref_map[match.group(1).strip().lower()] = match.group(2).strip()
    for match in INLINE_LINK_RE.finditer(body):
        yield match.group(2).strip(), match.start()
    for match in REF_USE_RE.finditer(body):
        label = match.group(1)
        ref_key = (match.group(2) or label).strip().lower()
        if ref_key in ref_map:
            yield ref_map[ref_key], match.start()


def check_markdown_links(project: ProjectRoot, md_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = read_text(md_path)
    except OSError as exc:
        return [f"cannot read {md_path.relative_to(project.root).as_posix()}: {exc}"]
    rel_md = md_path.relative_to(project.root).as_posix()
    for target, _pos in _iter_markdown_links(text):
        normalized = _normalize_link_destination(target)
        path_part = normalized.split("#", 1)[0]
        if _is_external_link(path_part):
            continue
        decoded = unquote(path_part)
        if not decoded:
            continue
        try:
            resolved = project.resolve_under(decoded, base=md_path.parent, allow_parent=True)
        except ValueError as exc:
            errors.append(f"{rel_md}: link {target!r} - {exc}")
            continue
        if not resolved.exists():
            errors.append(f"{rel_md}: broken link {target!r} -> {decoded}")
    return errors


def load_mapped_paths(project: ProjectRoot) -> set[str]:
    map_path = project.root / MAP_REL
    if not map_path.is_file():
        return set()
    try:
        obj = json.loads(read_text(map_path))
    except (json.JSONDecodeError, OSError):
        return set()
    entries = obj.get("entries", [])
    mapped: set[str] = set()
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                mapped.add(entry["path"].replace("\\", "/"))
    return mapped


def _should_ignore_unmapped(rel_posix: str) -> bool:
    if rel_posix in UNMAPPED_IGNORE_EXACT:
        return True
    for prefix in UNMAPPED_IGNORE_PREFIXES:
        if rel_posix.startswith(prefix):
            return True
    if "/__pycache__/" in f"/{rel_posix}/":
        return True
    if rel_posix.endswith(".pyc"):
        return True
    return False


def iter_unmapped_surfaces(project: ProjectRoot) -> list[str]:
    mapped = load_mapped_paths(project)
    found: set[str] = set()

    def add_if_doc(path: Path) -> None:
        if not path.is_file():
            return
        rel = path.relative_to(project.root).as_posix()
        if _should_ignore_unmapped(rel):
            return
        if rel not in mapped:
            found.add(rel)

    for name in ("README.md", "AGENTS.md"):
        add_if_doc(project.root / name)

    for pattern in ("*.md", "*.json", "*.yaml", "*.yml"):
        for path in (project.root / "docs").rglob(pattern):
            add_if_doc(path)

    templates = project.root / "templates"
    if templates.is_dir():
        for path in templates.rglob("*"):
            if path.is_file():
                add_if_doc(path)

    for script in PROJECT_DOCS_SCRIPTS:
        add_if_doc(project.root / script)

    return sorted(found)


def audit_markdown_files(project: ProjectRoot) -> list[str]:
    errors: list[str] = []
    targets: set[Path] = set()
    mapped = load_mapped_paths(project)
    for rel in mapped:
        candidate = project.root / rel.replace("/", os.sep)
        if candidate.suffix.lower() == ".md" and candidate.is_file():
            targets.add(candidate.resolve())
    for rel in ("README.md", "AGENTS.md"):
        p = project.root / rel
        if p.is_file():
            targets.add(p.resolve())
    docs_dir = project.root / "docs"
    if docs_dir.is_dir():
        for path in docs_dir.rglob("*.md"):
            targets.add(path.resolve())
    for path in sorted(targets):
        errors.extend(check_markdown_links(project, path))
    return errors


def run_audit(project: ProjectRoot, *, strict_unmapped: bool) -> AuditResult:
    result = AuditResult()
    for msg in validate_docs_map(project):
        result.findings.append(Finding("docs-map", msg))
    for msg in audit_markdown_files(project):
        result.findings.append(Finding("markdown-link", msg))
    check_sync_marker(project, result)
    unmapped = iter_unmapped_surfaces(project)
    if unmapped:
        summary = "unmapped documentation surfaces: " + ", ".join(unmapped)
        if strict_unmapped:
            result.findings.append(Finding("unmapped", summary))
        else:
            result.warnings.append(summary)
    return result


def print_audit(result: AuditResult) -> None:
    for finding in result.findings:
        print(f"FAIL [{finding.category}] {finding.message}")
    for warning in result.warnings:
        print(f"WARN {warning}")
    if not result.failed and not result.warnings:
        print("OK  project-docs audit clean")


def cmd_audit(project: ProjectRoot, strict_unmapped: bool) -> int:
    result = run_audit(project, strict_unmapped=strict_unmapped)
    print_audit(result)
    if result.failed:
        print(f"PROJECT_DOCS_AUDIT_FAIL: {len(result.findings)} finding(s)")
        return 1
    print("PROJECT_DOCS_AUDIT_PASS")
    return 0


def _normalize_repo_paths(project: ProjectRoot, paths: Iterable[str]) -> list[str]:
    normalized: set[str] = set()
    for raw in paths:
        rel = project.rel(raw)
        normalized.add(rel)
    return sorted(normalized)


def cmd_impact(
    project: ProjectRoot,
    *,
    contract_id: str,
    paths: list[str],
    map_entries: list[str],
    validator_run: str,
    validator_exit_code: int | None,
    notes: str,
) -> int:
    if validator_run not in {"yes", "no"}:
        print("FAIL validator_run must be yes or no", file=sys.stderr)
        return 1
    try:
        docs_paths = _normalize_repo_paths(project, paths)
        map_paths = _normalize_repo_paths(project, map_entries) if map_entries else []
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1

    record: dict[str, Any] = {
        "contract_id": contract_id,
        "docs_paths_touched": docs_paths,
        "docs_map_entries_updated": map_paths,
        "validator_run": validator_run,
        "validator_exit_code": validator_exit_code,
        "notes": notes,
    }
    print(json.dumps(record, indent=2, sort_keys=False, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Project documentation lifecycle")
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--project-root",
        default=".",
        help="Repository root (default: current directory)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser(
        "audit",
        parents=[parent],
        help="Audit docs-map, links, unmapped, sync marker",
    )
    audit_p.add_argument(
        "--strict-unmapped",
        action="store_true",
        help="Treat unmapped documentation surfaces as failures",
    )

    sync_p = sub.add_parser(
        "sync-marker",
        parents=[parent],
        help="Check or write STATUS sync marker in project-state.md",
    )
    sync_p.add_argument(
        "--write",
        action="store_true",
        help="Atomically update sync marker (default: check only)",
    )

    impact_p = sub.add_parser("impact", parents=[parent], help="Emit Docs Impact Record JSON")
    impact_p.add_argument("--contract-id", required=True)
    impact_p.add_argument("--paths", nargs="*", default=[])
    impact_p.add_argument("--map-entries", nargs="*", default=[])
    impact_p.add_argument("--validator-run", required=True, choices=["yes", "no"])
    impact_p.add_argument("--validator-exit-code", type=int, default=None)
    impact_p.add_argument("--notes", default="")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        project = ProjectRoot(Path(args.project_root))
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1

    if args.command == "audit":
        return cmd_audit(project, strict_unmapped=args.strict_unmapped)
    if args.command == "sync-marker":
        return cmd_sync_marker(project, write=args.write)
    if args.command == "impact":
        return cmd_impact(
            project,
            contract_id=args.contract_id,
            paths=args.paths,
            map_entries=args.map_entries,
            validator_run=args.validator_run,
            validator_exit_code=args.validator_exit_code,
            notes=args.notes,
        )
    parser.error(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
