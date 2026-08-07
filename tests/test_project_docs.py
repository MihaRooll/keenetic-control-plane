"""Tests for scripts/project-docs.py lifecycle module."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "project-docs.py"

_spec = importlib.util.spec_from_file_location("project_docs", SCRIPT)
assert _spec and _spec.loader
pd = importlib.util.module_from_spec(_spec)
sys.modules["project_docs"] = pd
_spec.loader.exec_module(pd)


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SCRIPT), *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def mini_project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    docs = root / "docs"
    docs.mkdir(parents=True)
    (docs / "STATUS.yaml").write_text(
        'updated: "2026-01-01"\n\ncurrent_phase:\n  id: "phase-a"\n',
        encoding="utf-8",
    )
    (docs / "project-state.md").write_text(
        "intro\n<!-- project-docs-sync: phase=phase-a updated=2026-01-01 -->\n",
        encoding="utf-8",
    )
    (docs / "hello.md").write_text("See [ok](ok.md)\n", encoding="utf-8")
    (docs / "ok.md").write_text("ok\n", encoding="utf-8")
    (root / "README.md").write_text("# root\n", encoding="utf-8")
    map_obj = {
        "version": 1,
        "entries": [
            {
                "path": "docs/hello.md",
                "title": "Hello",
                "status": "active",
                "owners": ["team"],
            },
            {
                "path": "README.md",
                "title": "Readme",
                "status": "active",
                "owners": ["team"],
            },
        ],
    }
    (docs / "docs-map.json").write_text(json.dumps(map_obj, indent=2), encoding="utf-8")
    return root


def test_resolve_rejects_traversal_outside_root(mini_project: Path) -> None:
    project = pd.ProjectRoot(mini_project)
    md = mini_project / "docs" / "linker.md"
    outside = mini_project.parent / "outside.md"
    outside.write_text("nope\n", encoding="utf-8")
    md.write_text("[x](../../outside.md)\n", encoding="utf-8")
    errors = pd.check_markdown_links(project, md)
    assert len(errors) == 1
    assert "escapes" in errors[0]


def test_resolve_rejects_absolute(mini_project: Path) -> None:
    project = pd.ProjectRoot(mini_project)
    with pytest.raises(ValueError, match="absolute"):
        project.resolve_under("C:/outside.txt")


def test_symlink_outside_root_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink test requires elevated privileges on Windows")
    root = tmp_path / "proj"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("secret", encoding="utf-8")
    root.mkdir()
    link = root / "link.md"
    link.symlink_to(outside / "secret.md")
    project = pd.ProjectRoot(root)
    with pytest.raises(ValueError, match="escapes"):
        project.resolve_under("link.md")


def test_markdown_links_skip_code_fences(mini_project: Path) -> None:
    md = mini_project / "docs" / "fence.md"
    md.write_text("```md\n[bad](missing.md)\n```\n[good](ok.md)\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    errors = pd.check_markdown_links(project, md)
    assert errors == []


def test_markdown_links_skip_inline_code(mini_project: Path) -> None:
    md = mini_project / "docs" / "inline-code.md"
    md.write_text("Use `` `[missing](nope.md)` `` and [good](ok.md)\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    errors = pd.check_markdown_links(project, md)
    assert errors == []


def test_markdown_links_normalize_titles_and_angle_brackets(mini_project: Path) -> None:
    md = mini_project / "docs" / "normalized.md"
    md.write_text(
        '[titled](ok.md "title")\n'
        "[bracketed](<ok.md>)\n"
        '[both](<ok.md> "also")\n',
        encoding="utf-8",
    )
    project = pd.ProjectRoot(mini_project)
    assert pd.check_markdown_links(project, md) == []


def test_markdown_links_report_broken(mini_project: Path) -> None:
    md = mini_project / "docs" / "broken.md"
    md.write_text("[x](missing.md)\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    errors = pd.check_markdown_links(project, md)
    assert len(errors) == 1
    assert "broken link" in errors[0]


def test_markdown_links_ignore_external_and_mailto(mini_project: Path) -> None:
    md = mini_project / "docs" / "external.md"
    md.write_text(
        "[a](https://example.com)\n[b](#anchor)\n[c](mailto:a@b.com)\n",
        encoding="utf-8",
    )
    project = pd.ProjectRoot(mini_project)
    assert pd.check_markdown_links(project, md) == []


def test_markdown_links_ignore_angle_bracket_external_url(mini_project: Path) -> None:
    md = mini_project / "docs" / "angle-external.md"
    md.write_text("[x](<https://example.com>)\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    assert pd.check_markdown_links(project, md) == []


def test_markdown_links_angle_bracket_local_with_fragment(mini_project: Path) -> None:
    md = mini_project / "docs" / "angle-fragment.md"
    md.write_text("[x](<ok.md#frag>)\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    assert pd.check_markdown_links(project, md) == []


def test_unmapped_non_strict_warn_only(mini_project: Path) -> None:
    (mini_project / "AGENTS.md").write_text("# agents\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    result = pd.run_audit(project, strict_unmapped=False)
    assert not result.failed
    assert any("unmapped" in w for w in result.warnings)


def test_unmapped_strict_fails(mini_project: Path) -> None:
    (mini_project / "AGENTS.md").write_text("# agents\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    result = pd.run_audit(project, strict_unmapped=True)
    assert result.failed
    assert any(f.category == "unmapped" for f in result.findings)


def test_sync_marker_check_and_write(mini_project: Path) -> None:
    state = mini_project / "docs" / "project-state.md"
    state.write_text("prose only\n", encoding="utf-8")
    project = pd.ProjectRoot(mini_project)
    assert pd.cmd_sync_marker(project, write=False) == 1
    assert pd.cmd_sync_marker(project, write=True) == 0
    assert pd.cmd_sync_marker(project, write=False) == 0
    text = state.read_text(encoding="utf-8")
    assert "project-docs-sync" in text
    assert "prose only" in text


def test_sync_marker_write_is_atomic(mini_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = mini_project / "docs" / "project-state.md"
    original = state.read_text(encoding="utf-8")
    project = pd.ProjectRoot(mini_project)

    real_replace = os.replace

    def flaky_replace(src: str, dst: str) -> None:
        if Path(dst).name == "project-state.md":
            raise OSError("simulated failure")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    with pytest.raises(OSError):
        pd.write_sync_marker(project)
    assert state.read_text(encoding="utf-8") == original


def _seed_status_and_state(docs_dir: Path) -> None:
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "STATUS.yaml").write_text(
        'updated: "2026-01-01"\n\ncurrent_phase:\n  id: "phase-a"\n',
        encoding="utf-8",
    )
    (docs_dir / "project-state.md").write_text(
        "intro\n<!-- project-docs-sync: phase=phase-a updated=2026-01-01 -->\n",
        encoding="utf-8",
    )


def test_write_sync_marker_rejects_docs_outside_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    _seed_status_and_state(outside)
    root = tmp_path / "proj"
    root.mkdir()
    docs_link = root / "docs"

    if os.name == "nt":
        proc = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(docs_link), str(outside)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            pytest.skip(f"junction creation failed: {proc.stderr}")
    else:
        docs_link.symlink_to(outside, target_is_directory=True)

    project = pd.ProjectRoot(root)
    assert pd.write_sync_marker(project) == 1


def test_impact_deterministic_sorted(
    mini_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = pd.ProjectRoot(mini_project)
    code = pd.cmd_impact(
        project,
        contract_id="demo",
        paths=["docs/hello.md", "README.md", "docs/hello.md"],
        map_entries=["README.md", "docs/hello.md", "README.md"],
        validator_run="yes",
        validator_exit_code=0,
        notes="test",
    )
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["docs_paths_touched"] == ["README.md", "docs/hello.md"]
    assert data["docs_map_entries_updated"] == ["README.md", "docs/hello.md"]
    assert data["docs_paths_touched"] == sorted(set(data["docs_paths_touched"]))
    assert data["docs_map_entries_updated"] == sorted(set(data["docs_map_entries_updated"]))


def test_impact_rejects_outside_root(mini_project: Path) -> None:
    project = pd.ProjectRoot(mini_project)
    code = pd.cmd_impact(
        project,
        contract_id="demo",
        paths=["../outside.md"],
        map_entries=[],
        validator_run="no",
        validator_exit_code=None,
        notes="",
    )
    assert code == 1


def test_impact_cli_json_fields(mini_project: Path) -> None:
    proc = run_cli(
        "impact",
        "--project-root",
        str(mini_project),
        "--contract-id",
        "c1",
        "--paths",
        "README.md",
        "docs/hello.md",
        "--map-entries",
        "README.md",
        "--validator-run",
        "yes",
        "--validator-exit-code",
        "0",
        "--notes",
        "n",
        cwd=mini_project,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["contract_id"] == "c1"
    assert data["docs_paths_touched"] == ["README.md", "docs/hello.md"]
    assert data["docs_map_entries_updated"] == ["README.md"]
    assert data["validator_run"] == "yes"
    assert data["validator_exit_code"] == 0
    assert data["notes"] == "n"
    assert data["docs_paths_touched"] == sorted(set(data["docs_paths_touched"]))
    assert data["docs_map_entries_updated"] == sorted(set(data["docs_map_entries_updated"]))


def test_project_docs_ps1_audit_project_root_style(mini_project: Path) -> None:
    if os.name != "nt":
        pytest.skip("project-docs.ps1 wrapper is Windows-only")
    ps1 = REPO_ROOT / "scripts" / "project-docs.ps1"
    proc = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ps1),
            "audit",
            "--project-root",
            str(mini_project),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_audit_cli_exit_codes(mini_project: Path) -> None:
    ok = run_cli("audit", "--project-root", str(mini_project), cwd=mini_project)
    assert ok.returncode == 0
    (mini_project / "docs" / "bad.md").write_text("[x](nope.md)\n", encoding="utf-8")
    bad = run_cli("audit", "--project-root", str(mini_project), cwd=mini_project)
    assert bad.returncode == 1


def test_validate_docs_map_matches_selftest_fixtures() -> None:
    fixtures = REPO_ROOT / "tests" / "project-docs" / "fixtures"
    valid = pd.validate_docs_map(pd.ProjectRoot(fixtures / "valid"), "docs-map.json")
    assert valid == []
    assert pd.validate_docs_map(pd.ProjectRoot(fixtures / "invalid-schema"), "docs-map.json")
    assert pd.validate_docs_map(pd.ProjectRoot(fixtures / "invalid-missing-path"), "docs-map.json")
    assert pd.validate_docs_map(pd.ProjectRoot(fixtures / "invalid-absolute-path"), "docs-map.json")
    bracket = fixtures / "valid-bracket-unicode"
    assert pd.validate_docs_map(pd.ProjectRoot(bracket), "docs-map.json") == []


def test_repo_audit_passes() -> None:
    proc = run_cli("audit", "--project-root", str(REPO_ROOT))
    assert proc.returncode == 0, proc.stdout + proc.stderr
