"""Структурные и поведенческие контракты экрана «Диагностика» LOCAL HUB."""

# ruff: noqa: E501

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
DIAG_SCREEN_JS = HUB / "screens" / "diagnostics.js"
DIAG_MODEL_JS = HUB / "features" / "diagnostics-model.js"
SYSTEM_CHECK_JS = HUB / "features" / "system-check.js"
DOMAIN_MODEL_JS = HUB / "features" / "domain-model.js"
HARNESS_JS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

FORBIDDEN_DIAG_LITERALS = (
    "8 из 8",
    "46 мс",
    "Нидерланды",
    "Keenetic Hopper",
    "Система готова к работе",
    "renderStubScreen",
    "innerHTML",
    "localStorage",
    "sessionStorage",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function_body(source: str, signature: str) -> str | None:
    start = source.find(signature)
    if start == -1:
        return None
    paren = source.find("(", start)
    if paren == -1:
        return None
    depth = 0
    i = paren
    while i < len(source):
        char = source[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                brace = source.find("{", i + 1)
                if brace == -1:
                    return None
                body_depth = 0
                j = brace
                while j < len(source):
                    if source[j] == "{":
                        body_depth += 1
                    elif source[j] == "}":
                        body_depth -= 1
                        if body_depth == 0:
                            return source[brace + 1 : j]
                    j += 1
                return None
        i += 1
    return None


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            f"node is required for hub diagnostics tests; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _run_node_harness(script: str, tmp_path: Path, label: str) -> object:
    node = _require_node()
    tmp_path.mkdir(parents=True, exist_ok=True)
    harness_path = tmp_path / f"{label}.mjs"
    harness_path.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        [node, str(harness_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"node harness {label} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
    return json.loads(proc.stdout.strip())


def _run_model_export(tmp_path: Path, *, label: str, script_body: str) -> object:
    model_uri = DIAG_MODEL_JS.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def _run_system_check_export(tmp_path: Path, *, label: str, script_body: str) -> object:
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    script = f"const mod = await import({json.dumps(sc_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def test_failed_badge_tone_is_neutral(tmp_path: Path) -> None:
    """FAILED/unknown badgeTone — neutral, не warning (через evaluateSystemCheck)."""
    result = _run_system_check_export(
        tmp_path,
        label="failed-badge-tone",
        script_body="""
const verdict = mod.evaluateSystemCheck({
  health: null,
  routerPresent: true,
  hostKeyConfirmed: false,
  adapterMode: 'live',
});
console.log(JSON.stringify({ level: verdict.level, badgeTone: verdict.badgeTone }));
""",
    )
    assert result["level"] == "FAILED"
    assert result["badgeTone"] == "neutral", (
        f"expected neutral badgeTone for FAILED, got {result['badgeTone']!r}"
    )


def test_host_internet_success_does_not_green_router_internet(tmp_path: Path) -> None:
    """Успех host-side internet не окрашивает строку «Интернет у роутера»."""
    domain_uri = DOMAIN_MODEL_JS.as_uri()
    result = _run_model_export(
        tmp_path,
        label="router-vs-host-internet",
        script_body=f"""
import {{ describeHostInternetProbe }} from {json.dumps(domain_uri)};
const hostRow = mod.buildHostInternetRow(
  describeHostInternetProbe({{ internet_reachable: true, reason_code: 'host_internet.reachable' }}),
);
const routerInternetOk = mod.buildRouterInternetRowFromObserve({{
  read_status: 'ok',
  internet: true,
}});
const routerInternetFailed = mod.buildRouterInternetRowFromObserve({{
  read_status: 'failed',
}});
console.log(JSON.stringify({{
  hostProvable: hostRow.provableState,
  hostHub: hostRow.hubState,
  routerOkProvable: routerInternetOk.provableState,
  routerFailedProvable: routerInternetFailed.provableState,
  routerFailedMessage: routerInternetFailed.message,
  incorrectlyShared: routerInternetFailed.provableState === hostRow.provableState,
}}));
""",
    )
    assert result["hostProvable"] == "green"
    assert result["hostHub"] == "SUCCESS"
    assert result["routerOkProvable"] == "green"
    assert result["routerFailedProvable"] == "unknown"
    assert result["incorrectlyShared"] is False
    assert "не удалось проверить" in str(result["routerFailedMessage"]).lower()


def test_router_internet_observe_row_states(tmp_path: Path) -> None:
    """Строка «Интернет у роутера»: ok true/false и failed без ложных утверждений."""
    result = _run_model_export(
        tmp_path,
        label="router-internet-states",
        script_body="""
const okTrue = mod.buildRouterInternetRowFromObserve({ read_status: 'ok', internet: true });
const okFalse = mod.buildRouterInternetRowFromObserve({ read_status: 'ok', internet: false });
const failed = mod.buildRouterInternetRowFromObserve({ read_status: 'failed' });
console.log(JSON.stringify({
  okTrueProvable: okTrue.provableState,
  okFalseProvable: okFalse.provableState,
  failedProvable: failed.provableState,
  okFalseMessage: okFalse.message,
  failedMessage: failed.message,
}));
""",
    )
    assert result["okTrueProvable"] == "green"
    assert result["okFalseProvable"] == "red"
    assert result["failedProvable"] == "unknown"
    assert "интернет" in str(result["okFalseMessage"]).lower()
    assert "не удалось проверить" in str(result["failedMessage"]).lower()
    assert "есть интернет" not in str(result["failedMessage"]).lower()


def test_counter_excludes_unsupported_and_unknown_rows(tmp_path: Path) -> None:
    """Счётчик учитывает только доказуемые строки группы 1."""
    result = _run_model_export(
        tmp_path,
        label="counter-subset",
        script_body="""
const group1 = [
  mod.buildRouterRowFromVerdict({
    level: 'READY',
    hubState: 'SUCCESS',
    title: 'ok',
    description: 'ok',
    badgeLabel: 'Гotovo',
    badgeTone: 'success',
    reasonCode: 'all_facts_healthy',
    facts: [],
    host: null,
    routerId: 'r1',
    mock: false,
    mockNote: null,
    checkedAt: new Date(),
  }, { adapterMode: 'live' }),
  mod.buildCredentialsRow(true),
  mod.buildWifiRowFromObserved(
    { readable: true, ssid: 'StaffNet', ssidLabel: 'StaffNet', hubState: 'SUCCESS', activeLabel: 'Включена', activeTone: 'success', technicalLines: ['ap'] },
    { title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'live', enabledOrUp: true },
  ),
  mod.buildRouterInternetRow(),
  mod.buildWifiRowFromObserved(null, { title: 'Гостевая сеть', apId: null, apMissing: true }),
];
const counter = mod.computeReadinessCounter(group1, 'live');
console.log(JSON.stringify({ label: counter.label, green: counter.green, total: counter.total }));
""",
    )
    assert result["label"] == "2 из 2"
    assert result["total"] == 2
    assert result["label"] != "5 из 5"


def test_fake_adapter_mode_never_success_readiness_tone(tmp_path: Path) -> None:
    result = _run_model_export(
        tmp_path,
        label="fake-no-success",
        script_body="""
const verdict = {
  level: 'READY',
  hubState: 'SUCCESS',
  title: 'Ready title',
  description: 'ok',
  badgeLabel: 'Гotovo',
  badgeTone: 'success',
  reasonCode: 'all_facts_healthy',
  facts: [],
  host: null,
  routerId: 'r1',
  mock: true,
  mockNote: 'demo',
  checkedAt: new Date(),
};
const group1 = [
  mod.buildRouterRowFromVerdict(verdict, { adapterMode: 'fake' }),
  mod.buildWifiRowFromObserved(
    { readable: true, ssid: 'X', ssidLabel: 'X', hubState: 'SUCCESS', activeLabel: 'Включена', activeTone: 'success', technicalLines: [] },
    { title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'fake', enabledOrUp: true },
  ),
];
const counter = mod.computeReadinessCounter(group1, 'fake');
const banner = mod.computeSummaryBanner({ systemVerdict: verdict, counter, adapterMode: 'fake', group1Rows: group1 });
console.log(JSON.stringify({ bannerTone: banner.tone, counterLabel: counter.label, total: counter.total }));
""",
    )
    assert result["bannerTone"] != "success"
    assert result["total"] == 0


def test_missing_probe_preconditions_unknown_without_request(tmp_path: Path) -> None:
    result = _run_model_export(
        tmp_path,
        label="missing-preconditions",
        script_body="""
const ctx = mod.resolveLocalApplicationProbeContext({ eventPresetId: null }, null, null);
const httpRow = mod.buildLocalAppHttpRow({}, { skipped: true, skipReason: ctx.missingReason });
const tlsRow = mod.buildLocalAppTlsRow({}, { skipped: true, skipReason: ctx.missingReason });
console.log(JSON.stringify({
  httpProvable: httpRow.provableState,
  tlsProvable: tlsRow.provableState,
  httpHub: httpRow.hubState,
  shouldProbe: ctx.hasAddress,
}));
""",
    )
    assert result["shouldProbe"] is False
    assert result["httpProvable"] == "unknown"
    assert result["tlsProvable"] == "unknown"
    assert result["httpHub"] != "ERROR"


def test_tls_row_green_only_when_aggregate_ok(tmp_path: Path) -> None:
    domain_uri = DOMAIN_MODEL_JS.as_uri()
    result = _run_model_export(
        tmp_path,
        label="tls-aggregate",
        script_body=f"""
import {{ describeHostTlsProbe }} from {json.dumps(domain_uri)};
const warningRow = mod.buildLocalAppTlsRow(
  describeHostTlsProbe({{ aggregate_status: 'warning', reachable: true, reason_code: 'host_tls.untrusted_issuer' }}),
);
const okRow = mod.buildLocalAppTlsRow(
  describeHostTlsProbe({{ aggregate_status: 'ok', reachable: true, reason_code: 'host_tls.ok' }}),
);
console.log(JSON.stringify({{
  warningProvable: warningRow.provableState,
  warningHub: warningRow.hubState,
  okProvable: okRow.provableState,
  okHub: okRow.hubState,
}}));
""",
    )
    assert result["okProvable"] == "green"
    assert result["okHub"] == "SUCCESS"
    assert result["warningProvable"] != "green"
    assert result["warningHub"] != "SUCCESS"


def test_stale_diagnostics_generation_not_applied(tmp_path: Path) -> None:
    """Старый generation не перезаписывает более новый результат."""
    result = _run_model_export(
        tmp_path,
        label="stale-generation",
        script_body="""
const stale = mod.shouldAcceptDiagnosticsGeneration(1, 2);
const fresh = mod.shouldAcceptDiagnosticsGeneration(2, 2);
console.log(JSON.stringify({ staleAccepted: stale, freshAccepted: fresh }));
""",
    )
    assert result["staleAccepted"] is False
    assert result["freshAccepted"] is True


def test_export_report_contains_no_secret_like_keys(tmp_path: Path) -> None:
    result = _run_model_export(
        tmp_path,
        label="export-sanitize",
        script_body="""
const snapshot = mod.assembleDiagnosticsSnapshot({
  rows: [mod.buildRouterInternetRow()],
  systemVerdict: null,
  checkedAt: new Date(),
}, 'live');
const report = mod.buildDiagnosticsExportReport({
  ...snapshot,
  rows: [
    ...snapshot.rows,
    {
      id: 'probe',
      group: 'host-probes',
      title: 'probe',
      message: 'm',
      hubState: 'WARNING',
      provableState: 'unknown',
      technical: 'password: hidden\\ncredential_ref: x',
    },
  ],
  nested_secrets: {
    password: 'super-secret',
    credential_ref: 'cred-123',
    router_credential_ref_id: 'rc-456',
    psk: 'wifi-psk-value',
    private_key: '-----BEGIN PRIVATE KEY-----',
    nested: { cookie: 'session-token', safe_field: 'ok' },
    items: [{ ssh_host_key: 'host-key-data', ssh_host_key_sha256: 'sha256:abc' }],
  },
});
const forbidden = mod.findForbiddenExportKeys(report);
const reportJson = JSON.stringify(report);
console.log(JSON.stringify({
  forbidden,
  hasRows: Array.isArray(report?.rows),
  jsonContainsPassword: reportJson.includes('super-secret'),
  jsonContainsCredentialRef: reportJson.includes('cred-123'),
  jsonContainsPsk: reportJson.includes('wifi-psk-value'),
  jsonContainsPrivateKey: reportJson.includes('BEGIN PRIVATE KEY'),
  jsonContainsCookie: reportJson.includes('session-token'),
  jsonContainsTechnicalPassword: reportJson.includes('password: hidden'),
}));
""",
    )
    assert result["forbidden"] == []
    assert result["jsonContainsPassword"] is False
    assert result["jsonContainsCredentialRef"] is False
    assert result["jsonContainsPsk"] is False
    assert result["jsonContainsPrivateKey"] is False
    assert result["jsonContainsCookie"] is False
    assert result["jsonContainsTechnicalPassword"] is False


def test_export_sanitize_removal_fails_without_sanitization(tmp_path: Path) -> None:
    """Доказывает, что тест экспорта реален: без sanitize forbidden keys остаются."""
    result = _run_model_export(
        tmp_path,
        label="export-no-sanitize",
        script_body="""
const payload = {
  password: 'super-secret',
  credential_ref: 'cred-123',
  nested: { psk: 'wifi-psk-value', cookie: 'session-token' },
  rows: [{ technical: 'password: hidden' }],
};
const forbidden = mod.findForbiddenExportKeys(payload);
console.log(JSON.stringify({ forbiddenCount: forbidden.length, forbidden }));
""",
    )
    assert result["forbiddenCount"] > 0


def test_banner_tone_headline_never_contradict(tmp_path: Path) -> None:
    """F-1: tone и headline согласованы; «Система готова к работе» не рендерится."""
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    result = _run_model_export(
        tmp_path,
        label="banner-matrix",
        script_body=f"""
import {{ evaluateSystemCheck, SystemCheckLevel }} from {json.dumps(sc_uri)};

const readyVerdict = evaluateSystemCheck({{
  health: {{
    status: 'green',
    reason_code: 'all_facts_healthy',
    facts: {{
      reachable: true,
      host_key_match: true,
      tuple_match: true,
      credentials_present: true,
      evidence_fresh: true,
    }},
  }},
  routerPresent: true,
  hostKeyConfirmed: true,
  adapterMode: 'live',
}});

const scenarios = [
  {{
    name: 'ready_all_green',
    systemVerdict: readyVerdict,
    group1: [
      mod.buildRouterRowFromVerdict(readyVerdict, {{ adapterMode: 'live' }}),
      mod.buildWifiRowFromObserved(
        {{ readable: true, ssid: 'Staff', ssidLabel: 'Staff', hubState: 'SUCCESS', technicalLines: [] }},
        {{ title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'live', enabledOrUp: true }},
      ),
      mod.buildWifiRowFromObserved(
        {{ readable: true, ssid: 'Guest', ssidLabel: 'Guest', hubState: 'SUCCESS', technicalLines: [] }},
        {{ title: 'Гостевая сеть', apId: 'ap2', adapterMode: 'live', enabledOrUp: true }},
      ),
    ],
  }},
  {{
    name: 'ready_wifi_red',
    systemVerdict: readyVerdict,
    group1: [
      mod.buildRouterRowFromVerdict(readyVerdict, {{ adapterMode: 'live' }}),
      mod.buildWifiRowFromObserved(
        {{ readable: true, ssid: 'Staff', ssidLabel: 'Staff', hubState: 'SUCCESS', technicalLines: [] }},
        {{ title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'live', enabledOrUp: false }},
      ),
    ],
  }},
  {{
    name: 'ready_wifi_unknown',
    systemVerdict: readyVerdict,
    group1: [
      mod.buildRouterRowFromVerdict(readyVerdict, {{ adapterMode: 'live' }}),
      mod.buildWifiRowFromObserved(null, {{ title: 'Гостевая сеть', apId: null, apMissing: true }}),
    ],
  }},
  {{
    name: 'failed_health',
    systemVerdict: evaluateSystemCheck({{ health: null, routerPresent: true, hostKeyConfirmed: false, adapterMode: 'live' }}),
    group1: [mod.buildRouterRowFromVerdict(
      evaluateSystemCheck({{ health: null, routerPresent: true, hostKeyConfirmed: false, adapterMode: 'live' }}),
      {{ adapterMode: 'live' }},
    )],
  }},
  {{
    name: 'not_ready',
    systemVerdict: evaluateSystemCheck({{
      health: {{ status: 'red', reason_code: 'unreachable', facts: {{ reachable: false }} }},
      routerPresent: true,
      hostKeyConfirmed: true,
      adapterMode: 'live',
    }}),
    group1: [mod.buildRouterRowFromVerdict(
      evaluateSystemCheck({{
        health: {{ status: 'red', reason_code: 'unreachable', facts: {{ reachable: false }} }},
        routerPresent: true,
        hostKeyConfirmed: true,
        adapterMode: 'live',
      }}),
      {{ adapterMode: 'live' }},
    )],
  }},
];

const readyPhrases = [/готова к работе/i, /система готова/i];
const failurePhrases = [/не пройден/i, /не установлен/i];
const violations = [];

for (const scenario of scenarios) {{
  const counter = mod.computeReadinessCounter(scenario.group1, 'live');
  const banner = mod.computeSummaryBanner({{
    systemVerdict: scenario.systemVerdict,
    counter,
    adapterMode: 'live',
    group1Rows: scenario.group1,
  }});
  if (banner.title === 'Система готова к работе') {{
    violations.push({{ scenario: scenario.name, issue: 'forbidden_title' }});
  }}
  if (banner.tone === 'success' && failurePhrases.some((re) => re.test(banner.title))) {{
    violations.push({{ scenario: scenario.name, issue: 'success_with_failure_headline', banner }});
  }}
  if ((banner.tone === 'warning' || banner.tone === 'danger') && readyPhrases.some((re) => re.test(banner.title))) {{
    violations.push({{ scenario: scenario.name, issue: 'warning_danger_with_ready_headline', banner }});
  }}
  const hasFailedInM = scenario.group1.some((row) => mod.isRowCountable(row, 'live') && row.provableState === 'red');
  if (banner.tone === 'success' && hasFailedInM) {{
    violations.push({{ scenario: scenario.name, issue: 'success_with_failed_row', banner }});
  }}
}}

console.log(JSON.stringify({{ violations, scenarioCount: scenarios.length }}));
""",
    )
    assert result["violations"] == [], f"banner contradictions: {result['violations']}"


def test_diagnostics_connection_consistent_with_system_check(tmp_path: Path) -> None:
    """F-1 invariant: diagnostics connection statement не противоречит evaluateSystemCheck."""
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    result = _run_model_export(
        tmp_path,
        label="connection-invariant",
        script_body=f"""
import {{ evaluateSystemCheck, SystemCheckLevel }} from {json.dumps(sc_uri)};

const inputs = [
  {{ health: {{ status: 'green', reason_code: 'all_facts_healthy', facts: {{ reachable: true, host_key_match: true, tuple_match: true, credentials_present: true, evidence_fresh: true }} }}, routerPresent: true, hostKeyConfirmed: true }},
  {{ health: null, routerPresent: true, hostKeyConfirmed: false }},
  {{ health: {{ status: 'red', reason_code: 'unreachable', facts: {{ reachable: false }} }}, routerPresent: true, hostKeyConfirmed: true }},
  {{ health: null, routerPresent: false, hostKeyConfirmed: false }},
];

const mismatches = [];
for (const input of inputs) {{
  const verdict = evaluateSystemCheck({{ ...input, adapterMode: 'live' }});
  const group1 = [mod.buildRouterRowFromVerdict(verdict, {{ adapterMode: 'live' }})];
  const counter = mod.computeReadinessCounter(group1, 'live');
  const banner = mod.computeSummaryBanner({{ systemVerdict: verdict, counter, adapterMode: 'live', group1Rows: group1 }});
  if (verdict.level === SystemCheckLevel.READY && /не установлен/i.test(banner.title)) {{
    mismatches.push({{ level: verdict.level, title: banner.title }});
  }}
  if (verdict.level === SystemCheckLevel.NOT_READY && /подтверждена/i.test(banner.title)) {{
    mismatches.push({{ level: verdict.level, title: banner.title }});
  }}
  if (verdict.level === SystemCheckLevel.FAILED && banner.tone !== 'neutral') {{
    mismatches.push({{ level: verdict.level, tone: banner.tone }});
  }}
  if (verdict.level === SystemCheckLevel.FAILED && !/не проверен/i.test(banner.title)) {{
    mismatches.push({{ level: verdict.level, title: banner.title, issue: 'failed_should_say_unchecked' }});
  }}
}}

console.log(JSON.stringify({{ mismatches }}));
""",
    )
    assert result["mismatches"] == []


def test_wifi_enabled_or_up_ssid_truth_table(tmp_path: Path) -> None:
    """F-2: полная таблица (enabled_or_up × ssid) для Wi‑Fi строк."""
    result = _run_model_export(
        tmp_path,
        label="wifi-truth-table",
        script_body="""
const observedBase = { readable: true, ssidLabel: 'Label', hubState: 'SUCCESS', technicalLines: [] };
const cases = [];
for (const enabledOrUp of [true, false, null]) {
  for (const ssid of ['NetName', null]) {
    const observed = { ...observedBase, ssid };
    const row = mod.buildWifiRowFromObserved(observed, {
      title: 'Рабочая сеть',
      apId: 'ap1',
      adapterMode: 'live',
      enabledOrUp,
    });
    cases.push({ enabledOrUp, ssid, provableState: row.provableState, hubState: row.hubState });
  }
}
const violations = cases.filter((c) => {
  if (c.enabledOrUp === true && c.ssid != null) {
    return c.provableState !== 'green' || c.hubState !== 'SUCCESS';
  }
  if (c.enabledOrUp === false) {
    return c.provableState !== 'red' || c.hubState === 'SUCCESS';
  }
  return c.provableState !== 'unknown' || c.hubState === 'SUCCESS' || c.hubState === 'WARNING' || c.hubState === 'ERROR';
});
console.log(JSON.stringify({ cases, violations }));
""",
    )
    assert result["violations"] == [], f"wifi truth table violations: {result['violations']}"


def test_null_health_excluded_from_counter(tmp_path: Path) -> None:
    """F-3: null health (FAILED) не считается доказанным провалом в счётчике."""
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    result = _run_model_export(
        tmp_path,
        label="failed-excluded-counter",
        script_body=f"""
import {{ evaluateSystemCheck }} from {json.dumps(sc_uri)};
const verdict = evaluateSystemCheck({{ health: null, routerPresent: true, hostKeyConfirmed: false, adapterMode: 'live' }});
const row = mod.buildRouterRowFromVerdict(verdict, {{ adapterMode: 'live' }});
const group1 = [row];
const counter = mod.computeReadinessCounter(group1, 'live');
console.log(JSON.stringify({{
  level: verdict.level,
  provableState: row.provableState,
  counterLabel: counter.label,
  total: counter.total,
  green: counter.green,
}}));
""",
    )
    assert result["level"] == "FAILED"
    assert result["provableState"] == "unknown"
    assert result["total"] == 0
    assert result["counterLabel"] == "—"
    assert "0 из 1" not in str(result["counterLabel"])


def test_unknown_rows_never_warning_error_success(tmp_path: Path) -> None:
    """F-4: все unknown строки рендерятся нейтрально."""
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    domain_uri = DOMAIN_MODEL_JS.as_uri()
    entry_pages_uri = (HUB / "features" / "entry-pages-model.js").as_uri()
    result = _run_model_export(
        tmp_path,
        label="unknown-neutral-all-rows",
        script_body=f"""
import {{ evaluateSystemCheck }} from {json.dumps(sc_uri)};
import {{ describeHostInternetProbe, describeHostHttpProbe, describeHostTlsProbe }} from {json.dumps(domain_uri)};
import {{ parseSelfCheckResult }} from {json.dumps(entry_pages_uri)};

const forbiddenHub = new Set(['WARNING', 'ERROR', 'SUCCESS']);
const rows = [];

const failedVerdict = evaluateSystemCheck({{ health: null, routerPresent: true, hostKeyConfirmed: false, adapterMode: 'live' }});
rows.push(mod.buildRouterRowFromVerdict(null, {{ adapterMode: 'live' }}));
rows.push(mod.buildRouterRowFromVerdict(failedVerdict, {{ adapterMode: 'live' }}));
rows.push(mod.buildWifiRowFromObserved(null, {{ title: 'Рабочая сеть', apId: 'ap1', readinessReason: 'missing params' }}));
rows.push(mod.buildWifiRowFromObserved(null, {{ title: 'Гостевая сеть', apId: null, apMissing: true }}));
rows.push(mod.buildWifiRowFromObserved(
  {{ readable: false, ssidLabel: 'unreadable', hubState: 'WARNING', technicalLines: [] }},
  {{ title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'live', enabledOrUp: null }},
));
rows.push(mod.buildWifiRowFromObserved(
  {{ readable: true, ssid: 'X', ssidLabel: 'X', hubState: 'SUCCESS', technicalLines: [] }},
  {{ title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'live', enabledOrUp: null }},
));
rows.push(mod.buildHostInternetRow(describeHostInternetProbe(null)));
rows.push(mod.buildLocalAppHttpRow(describeHostHttpProbe(null)));
rows.push(mod.buildLocalAppTlsRow(describeHostTlsProbe(null)));
rows.push(mod.buildEntryPageRow(parseSelfCheckResult(null).operatorRender));
rows.push(mod.buildLocalAppHttpRow(describeHostHttpProbe(null), {{ skipped: true }}));

const violations = rows
  .filter((row) => row.provableState === 'unknown')
  .filter((row) => forbiddenHub.has(row.hubState))
  .map((row) => ({{ id: row.id, hubState: row.hubState }}));

console.log(JSON.stringify({{ violations, unknownCount: rows.filter((r) => r.provableState === 'unknown').length }}));
""",
    )
    assert result["violations"] == [], f"unknown rows with non-neutral hub: {result['violations']}"


def test_ready_with_missing_aps_no_success_banner(tmp_path: Path) -> None:
    """F-5: connection ready + обе AP missing → не success tone, caption с unchecked."""
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    result = _run_model_export(
        tmp_path,
        label="ready-missing-aps",
        script_body=f"""
import {{ evaluateSystemCheck }} from {json.dumps(sc_uri)};
const verdict = evaluateSystemCheck({{
  health: {{
    status: 'green',
    reason_code: 'all_facts_healthy',
    facts: {{ reachable: true, host_key_match: true, tuple_match: true, credentials_present: true, evidence_fresh: true }},
  }},
  routerPresent: true,
  hostKeyConfirmed: true,
  adapterMode: 'live',
}});
const group1 = [
  mod.buildRouterRowFromVerdict(verdict, {{ adapterMode: 'live' }}),
  mod.buildWifiRowFromObserved(null, {{ title: 'Рабочая сеть', apId: null, apMissing: true }}),
  mod.buildWifiRowFromObserved(null, {{ title: 'Гостевая сеть', apId: null, apMissing: true }}),
];
const counter = mod.computeReadinessCounter(group1, 'live');
const banner = mod.computeSummaryBanner({{ systemVerdict: verdict, counter, adapterMode: 'live', group1Rows: group1 }});
console.log(JSON.stringify({{
  counterLabel: counter.label,
  bannerTone: banner.tone,
  caption: counter.caption,
  uncheckedCount: counter.uncheckedCount,
}}));
""",
    )
    assert result["counterLabel"] == "1 из 1"
    assert result["bannerTone"] != "success"
    assert result["uncheckedCount"] == 2
    assert "Не проверено: 2" in str(result["caption"])


def test_screen_uses_should_accept_generation_helper() -> None:
    source = _read(DIAG_SCREEN_JS)
    assert "shouldAcceptDiagnosticsGeneration" in source
    assert "gen === runGeneration" not in source.replace("shouldAcceptDiagnosticsGeneration(gen, runGeneration)", "")


def test_diagnostics_screen_imports_shared_generation_helper() -> None:
    source = _read(DIAG_SCREEN_JS)
    assert "import" in source and "shouldAcceptDiagnosticsGeneration" in source


def _run_diagnostics_mount_harness(tmp_path: Path, *, label: str, script_body: str) -> object:
    harness_path = json.dumps(str(HARNESS_JS))
    script = f"""import {{ createRequire }} from 'node:module';
const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_path});
const dom = createUiDomHarness();
globalThis.document = dom.document;
document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));
function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{ el.children.unshift(node); node.parentNode = el; }}
        else {{ el.appendChild(node); }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}
const _origCreateElement = document.createElement.bind(document);
document.createElement = (tag) => patchElement(_origCreateElement(tag));
globalThis.HTMLElement = document.createElement('div').constructor;
globalThis.HTMLInputElement = document.createElement('input').constructor;
globalThis.HTMLButtonElement = document.createElement('button').constructor;
Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});
globalThis.localStorage = dom.localStorage;
globalThis.window = dom.window;
window.removeEventListener = () => {{}};
globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
{script_body}
"""
    return _run_node_harness(script, tmp_path, label)


def test_diagnostics_screen_renders_single_h1_title(tmp_path: Path) -> None:
    """Экран «Диагностика» имеет ровно один h1 с заголовком экрана."""
    session_uri = json.dumps((HUB / "core" / "session.js").as_uri())
    screen_uri = json.dumps(DIAG_SCREEN_JS.as_uri())
    result = _run_diagnostics_mount_harness(
        tmp_path,
        label="diagnostics-h1",
        script_body=f"""
import {{ resetSession, updateSession }} from {session_uri};
import {{ render }} from {screen_uri};

globalThis.fetch = async () => ({{
  ok: true,
  status: 200,
  headers: {{ get: () => 'application/json' }},
  json: async () => ({{}}),
}});

resetSession();
updateSession({{ routerId: null, hostKeyConfirmed: false }});
const container = document.createElement('div');
document.body.appendChild(container);
const dispose = render(container, {{ runtime: {{ adapterMode: 'fake' }}, navigate: () => {{}}, showToast: () => {{}} }});
await new Promise((r) => setTimeout(r, 0));
const headings = [...container.querySelectorAll('h1')];
dispose();
console.log(JSON.stringify({{
  headingCount: headings.length,
  titleText: headings[0]?.textContent ?? null,
}}));
""",
    )
    assert result["headingCount"] == 1
    assert result["titleText"] == "Диагностика"


def test_diagnostics_caption_present_all_states(tmp_path: Path) -> None:
    """F-6: caption обязателен в loading, empty, error и fake."""
    session_uri = json.dumps((HUB / "core" / "session.js").as_uri())
    screen_uri = json.dumps(DIAG_SCREEN_JS.as_uri())
    model_uri = json.dumps(DIAG_MODEL_JS.as_uri())
    result = _run_diagnostics_mount_harness(
        tmp_path,
        label="caption-states",
        script_body=f"""
import {{ resetSession, updateSession }} from {session_uri};
import {{ render }} from {screen_uri};
import {{ READINESS_COUNTER_CAPTION }} from {model_uri};

const deferredHealth = [];
globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const u = String(url);
  if (method === 'POST' && u.includes('/lab/connection-health')) {{
    return new Promise((resolve) => {{ deferredHealth.push(resolve); }});
  }}
  if (method === 'GET' && u.includes('/hub/runtime.json')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ adapter_mode: 'live' }}) }};
  }}
  if (method === 'POST' && u.includes('/wifi/observed-state')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ access_points: [] }}) }};
  }}
  if (method === 'POST' && (u.includes('/host/internet') || u.includes('/host/http') || u.includes('/host/tls') || u.includes('/entry-pages'))) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
  }}
  if (method === 'GET' && u.includes('/entry-pages')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ items: [] }}) }};
  }}
  return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
}};

resetSession();
updateSession({{ routerId: 'r1', hostKeyConfirmed: true, wifiRoles: {{ staffApId: null, guestApId: null }} }});
const container = document.createElement('div');
document.body.appendChild(container);
const dispose = render(container, {{ runtime: {{ adapterMode: 'live' }}, navigate: () => {{}}, showToast: () => {{}} }});
await new Promise((r) => setTimeout(r, 0));
const loadingCaption = container.querySelector('[data-testid="diagnostics-counter-caption"]');
const loadingHasCaption = loadingCaption && loadingCaption.textContent.includes('Счётчик учитывает');

dispose();
while (container.firstChild) container.removeChild(container.firstChild);
resetSession();
updateSession({{ routerId: null, hostKeyConfirmed: false }});
const container2 = document.createElement('div');
document.body.appendChild(container2);
const dispose2 = render(container2, {{ runtime: {{ adapterMode: 'fake' }}, navigate: () => {{}}, showToast: () => {{}} }});
await new Promise((r) => setTimeout(r, 300));
const fakeCaption = container2.querySelector('[data-testid="diagnostics-counter-caption"]');
dispose2();

console.log(JSON.stringify({{
  loadingHasCaption,
  loadingText: loadingCaption?.textContent ?? null,
  fakeHasCaption: Boolean(fakeCaption && fakeCaption.textContent.includes('Счётчик учитывает')),
  captionConstant: READINESS_COUNTER_CAPTION.slice(0, 20),
}}));
""",
    )
    assert result["loadingHasCaption"] is True
    assert result["fakeHasCaption"] is True


def test_diagnostics_mount_stale_generation_not_applied(tmp_path: Path) -> None:
    """F-8: mount-level race — stale run не попадает в DOM."""
    session_uri = json.dumps((HUB / "core" / "session.js").as_uri())
    screen_uri = json.dumps(DIAG_SCREEN_JS.as_uri())
    result = _run_diagnostics_mount_harness(
        tmp_path,
        label="mount-race",
        script_body=f"""
const healthDeferreds = [];
let healthCall = 0;

globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const u = String(url);
  if (method === 'POST' && u.includes('/lab/connection-health')) {{
    healthCall += 1;
    const gen = healthCall;
    return new Promise((resolve) => {{ healthDeferreds.push({{ gen, resolve }}); }});
  }}
  if (method === 'GET' && u.includes('/hub/runtime.json')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ adapter_mode: 'live' }}) }};
  }}
  if (method === 'POST' && u.includes('/wifi/observed-state')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ access_points: [{{ ap_id: 'ap1', readable: true, ssid: 'S', enabled_or_up: true }}] }}) }};
  }}
  if (method === 'POST' && u.includes('/host/internet')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ internet_reachable: true, reason_code: 'host_internet.reachable' }}) }};
  }}
  if (method === 'POST' && (u.includes('/host/http') || u.includes('/host/tls'))) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ aggregate_status: 'ok', reachable: true }}) }};
  }}
  if (method === 'GET' && u.includes('/entry-pages')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ items: [] }}) }};
  }}
  if (method === 'GET' && u.includes('/event-presets')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
  }}
  return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
}};

const {{ resetSession, updateSession }} = await import({session_uri});
const {{ render }} = await import({screen_uri});

function healthPayload(label) {{
  return {{
    status: label === 'stale' ? 'red' : 'green',
    reason_code: label === 'stale' ? 'unreachable' : 'all_facts_healthy',
    facts: label === 'stale'
      ? {{ reachable: false }}
      : {{ reachable: true, host_key_match: true, tuple_match: true, credentials_present: true, evidence_fresh: true }},
  }};
}}

resetSession();
updateSession({{ routerId: 'r1', hostKeyConfirmed: true, wifiRoles: {{ staffApId: null, guestApId: null }} }});
const container = document.createElement('div');
document.body.appendChild(container);
const dispose = render(container, {{ runtime: {{ adapterMode: 'live' }}, navigate: () => {{}}, showToast: () => {{}} }});
await new Promise((r) => setTimeout(r, 20));

function findButtons(root) {{
  const out = [];
  function walk(node) {{
    if (!node || typeof node !== 'object') return;
    if (String(node.tagName || '').toUpperCase() === 'BUTTON') out.push(node);
    for (const child of node.children || []) walk(child);
  }}
  walk(root);
  return out;
}}

const rerunButtons = findButtons(container);
const rerunBtn = rerunButtons[0] ?? document.querySelector('button');
if (!rerunBtn) throw new Error(`rerun button missing, buttons=${{rerunButtons.length}} containerChildren=${{container.children?.length ?? 0}}`);
rerunBtn.disabled = false;
rerunBtn.click();
await new Promise((r) => setTimeout(r, 0));

const freshDeferred = healthDeferreds.find((d) => d.gen === 2);
const staleDeferred = healthDeferreds.find((d) => d.gen === 1);
if (!freshDeferred || !staleDeferred) throw new Error('expected two health calls');

freshDeferred.resolve({{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => healthPayload('fresh') }});
await new Promise((r) => setTimeout(r, 50));
const titleAfterFresh = container.querySelector('[data-testid="diagnostics-banner-title"]')?.textContent ?? '';

staleDeferred.resolve({{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => healthPayload('stale') }});
await new Promise((r) => setTimeout(r, 50));
const titleAfterStale = container.querySelector('[data-testid="diagnostics-banner-title"]')?.textContent ?? '';

const unmountContainer = document.createElement('div');
document.body.appendChild(unmountContainer);
const healthDeferredsUnmount = [];
let unmountHealthCall = 0;
const origFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const u = String(url);
  if (method === 'POST' && u.includes('/lab/connection-health')) {{
    unmountHealthCall += 1;
    return new Promise((resolve) => {{ healthDeferredsUnmount.push(resolve); }});
  }}
  return origFetch(url, init);
}};
const disposeUnmount = render(unmountContainer, {{ runtime: {{ adapterMode: 'live' }}, navigate: () => {{}}, showToast: () => {{}} }});
await new Promise((r) => setTimeout(r, 0));
disposeUnmount();
if (healthDeferredsUnmount.length > 0) {{
  healthDeferredsUnmount[0]({{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => healthPayload('stale') }});
}}
await new Promise((r) => setTimeout(r, 50));
const unmountBanner = unmountContainer.querySelector('[data-testid="diagnostics-banner-title"]');

dispose();
console.log(JSON.stringify({{
  healthCallCount: healthDeferreds.length,
  titleAfterFresh,
  titleAfterStale,
  staleDidNotOverwrite: titleAfterFresh === titleAfterStale,
  freshIsConfirmed: /подтвержден/i.test(titleAfterFresh),
  staleWouldBeNotReady: /не установлен/i.test('Связь с роутером не установлена'),
  unmountBannerAbsent: unmountBanner === null,
  unmountHealthStarted: unmountHealthCall >= 1,
}}));
""",
    )
    assert result["healthCallCount"] >= 2
    assert result["staleDidNotOverwrite"] is True
    assert result["freshIsConfirmed"] is True
    assert result["unmountBannerAbsent"] is True


def test_diagnostics_forbidden_literals_grep() -> None:
    combined = _read(DIAG_SCREEN_JS) + "\n" + _read(DIAG_MODEL_JS)
    for literal in FORBIDDEN_DIAG_LITERALS:
        assert literal not in combined, f"forbidden literal: {literal}"


def test_diagnostics_screen_exports_meta_and_render() -> None:
    source = _read(DIAG_SCREEN_JS)
    assert "export const meta" in source
    assert "id: 'diagnostics'" in source
    assert "export function render(container, ctx)" in source
    assert "return () => {" in source
    assert "renderStubScreen" not in source


def test_diagnostics_sw_cache_lists_model() -> None:
    sw = _read(HUB / "sw.js")
    assert "features/diagnostics-model.js" in sw
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", sw)
    assert version_match is not None
    assert int(version_match.group(1)) >= 16


def test_diagnostics_api_failure_does_not_claim_publication_state(tmp_path: Path) -> None:
    """F-1: сбой preset/self-check не выдаёт факты о публикации и чужой CTA."""
    domain_uri = DOMAIN_MODEL_JS.as_uri()
    entry_pages_uri = (HUB / "features" / "entry-pages-model.js").as_uri()
    result = _run_model_export(
        tmp_path,
        label="api-failure-honesty",
        script_body=f"""
import {{ describeHostHttpProbe, describeHostTlsProbe }} from {json.dumps(domain_uri)};
import {{ parseSelfCheckResult }} from {json.dumps(entry_pages_uri)};

const httpFailed = mod.buildLocalAppHttpRow(null, {{ failed: true }});
const tlsFailed = mod.buildLocalAppTlsRow(null, {{ failed: true }});
const entryFailed = mod.buildEntryPageRow(null, {{ failed: true }});
const httpNullDescribed = mod.buildLocalAppHttpRow(describeHostHttpProbe(null));
const entryNullDescribed = mod.buildEntryPageRow(parseSelfCheckResult(null).operatorRender);

function violates(row) {{
  const msg = String(row.message ?? '').toLowerCase();
  return (
    msg.includes('не опубликована')
    || msg.includes('опубликован')
    || msg.includes('проверить доступность')
  );
}}

console.log(JSON.stringify({{
  httpFailed: httpFailed.message,
  tlsFailed: tlsFailed.message,
  entryFailed: entryFailed.message,
  httpNullHasCta: String(httpNullDescribed.message).includes('Проверить доступность'),
  entryNullClaimsPublication: violates(entryNullDescribed),
  failedRowsClean: ![httpFailed, tlsFailed, entryFailed].some(violates),
}}));
""",
    )
    assert result["failedRowsClean"] is True
    assert "не получены" in str(result["httpFailed"]).lower() or "не завершена" in str(result["httpFailed"]).lower()
    assert "не получены" in str(result["entryFailed"]).lower() or "не завершена" in str(result["entryFailed"]).lower()
    assert result["httpNullHasCta"] is False
    assert result["entryNullClaimsPublication"] is False


def test_unknown_rows_no_refusal_lexicon(tmp_path: Path) -> None:
    """F-4: unknown-строки не содержат refusal-лексику."""
    sc_uri = SYSTEM_CHECK_JS.as_uri()
    domain_uri = DOMAIN_MODEL_JS.as_uri()
    entry_pages_uri = (HUB / "features" / "entry-pages-model.js").as_uri()
    result = _run_model_export(
        tmp_path,
        label="unknown-refusal-lexicon",
        script_body=f"""
import {{ evaluateSystemCheck }} from {json.dumps(sc_uri)};
import {{ describeHostInternetProbe, describeHostHttpProbe, describeHostTlsProbe }} from {json.dumps(domain_uri)};
import {{ parseSelfCheckResult }} from {json.dumps(entry_pages_uri)};

const refusal = ['не удалось', 'не прочитан', 'недоступ', 'ошибка', 'не совпада', 'сбой', 'отказ'];
const rows = [];

const failedVerdict = evaluateSystemCheck({{ health: null, routerPresent: true, hostKeyConfirmed: false, adapterMode: 'live' }});
rows.push(mod.buildRouterRowFromVerdict(null, {{ adapterMode: 'live' }}));
rows.push(mod.buildRouterRowFromVerdict(failedVerdict, {{ adapterMode: 'live' }}));
rows.push(mod.buildWifiRowFromObserved(null, {{ title: 'Рабочая сеть', apId: 'ap1', readinessReason: 'missing params' }}));
rows.push(mod.buildWifiRowFromObserved(null, {{ title: 'Гостевая сеть', apId: null, apMissing: true }}));
rows.push(mod.buildWifiRowFromObserved(
  {{ readable: false, ssidLabel: 'unreadable', hubState: 'WARNING', technicalLines: [] }},
  {{ title: 'Рабочая сеть', apId: 'ap1', adapterMode: 'live', enabledOrUp: null }},
));
rows.push(mod.buildHostInternetRow(describeHostInternetProbe(null)));
rows.push(mod.buildHostInternetRow(describeHostInternetProbe({{ reason_code: 'host_internet.pending' }})));
rows.push(mod.buildLocalAppHttpRow(describeHostHttpProbe(null)));
rows.push(mod.buildLocalAppHttpRow(null, {{ failed: true }}));
rows.push(mod.buildLocalAppTlsRow(describeHostTlsProbe(null)));
rows.push(mod.buildEntryPageRow(parseSelfCheckResult(null).operatorRender));
rows.push(mod.buildEntryPageRow(null, {{ failed: true }}));
rows.push(mod.buildLocalAppHttpRow(null, {{ skipped: true, skipReason: mod.LOCAL_APP_ADDRESS_MISSING_MESSAGE }}));
rows.push(mod.buildEntryPageRow(null, {{ skipped: true }}));

const violations = [];
for (const row of rows) {{
  if (row.provableState !== 'unknown') continue;
  const msg = String(row.message ?? '').toLowerCase();
  for (const word of refusal) {{
    if (msg.includes(word)) violations.push({{ id: row.id, word, message: row.message }});
  }}
}}

console.log(JSON.stringify({{ violations, unknownCount: rows.filter((r) => r.provableState === 'unknown').length }}));
""",
    )
    assert result["violations"] == [], f"refusal lexicon in unknown rows: {result['violations']}"


def test_diagnostics_model_rethrows_when_system_check_fails(tmp_path: Path) -> None:
    """F-5: сбой connection-health пробрасывается — экран может сохранить stale snapshot."""
    result = _run_model_export(
        tmp_path,
        label="system-check-rethrow",
        script_body="""
let healthCalls = 0;
globalThis.fetch = async (url, init = {}) => {
  const method = init.method ?? 'GET';
  const u = String(url);
  if (method === 'POST' && u.includes('/lab/connection-health')) {
    healthCalls += 1;
    return { ok: false, status: 503, headers: { get: () => 'application/json' }, json: async () => ({ detail: 'fail' }) };
  }
  return { ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => ({}) };
};
let threw = false;
try {
  await mod.runDiagnosticsChecks({
    session: { routerId: 'r1', hostKeyConfirmed: true, wifiRoles: { staffApId: 'ap1', guestApId: null } },
    adapterMode: 'live',
    hostKeyConfirmed: true,
    routerPresent: true,
    routerId: 'r1',
  });
} catch (_err) {
  threw = true;
}
console.log(JSON.stringify({ threw, healthCalls }));
""",
    )
    assert result["threw"] is True
    assert result["healthCalls"] == 1


def test_diagnostics_screen_marks_stale_snapshot_on_rerun_error() -> None:
    """F-5: экран помечает устаревшие данные и не выдаёт свежий banner при lastError."""
    source = _read(DIAG_SCREEN_JS)
    assert "предыдущей успешной проверки" in source
    assert "устарели" in source
    assert "lastError && snapshot" in source
    assert "snapshotStale" in source


def test_diagnostics_stale_snapshot_on_rerun_failure(tmp_path: Path) -> None:
    """F-5 (mount): повторный прогон с ошибкой сохраняет строки и помечает timestamp."""
    session_uri = json.dumps((HUB / "core" / "session.js").as_uri())
    screen_uri = json.dumps(DIAG_SCREEN_JS.as_uri())
    result = _run_diagnostics_mount_harness(
        tmp_path,
        label="stale-on-rerun-fail",
        script_body=f"""
const {{ resetSession, updateSession }} = await import({session_uri});
const {{ render }} = await import({screen_uri});

let call = 0;
globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const u = String(url);
  if (method === 'GET' && u.includes('/hub/runtime.json')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ adapter_mode: 'live' }}) }};
  }}
  if (method === 'POST' && u.includes('/lab/connection-health')) {{
    call += 1;
    if (call === 1) {{
      return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{
        status: 'green', reason_code: 'all_facts_healthy',
        facts: {{ reachable: true, host_key_match: true, tuple_match: true, credentials_present: true, evidence_fresh: true }},
      }}) }};
    }}
    return {{ ok: false, status: 503, headers: {{ get: () => 'application/json' }}, json: async () => ({{ detail: 'fail' }}) }};
  }}
  if (method === 'POST' && u.includes('/wifi/observed-state')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ access_points: [{{ ap_id: 'ap1', enabled_or_up: true, ssid: 'Net' }}] }}) }};
  }}
  if (method === 'POST' && (u.includes('/lab/host-internet-probe') || u.includes('/lab/host-http-probe') || u.includes('/lab/host-tls-probe'))) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
  }}
  if (method === 'GET' && u.includes('/entry-pages')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ items: [] }}) }};
  }}
  return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
}};

function findButtons(root) {{
  const out = [];
  function walk(node) {{
    if (!node || typeof node !== 'object') return;
    if (String(node.tagName || '').toUpperCase() === 'BUTTON') out.push(node);
    for (const child of node.children || []) walk(child);
  }}
  walk(root);
  return out;
}}

resetSession();
updateSession({{ routerId: 'r1', hostKeyConfirmed: true, wifiRoles: {{ staffApId: 'ap1', guestApId: null }} }});
const container = document.createElement('div');
document.body.appendChild(container);
const dispose = render(container, {{ runtime: {{ adapterMode: 'live' }}, navigate: () => {{}}, showToast: () => {{}} }});
await new Promise((r) => setTimeout(r, 800));
const rerunBtn = findButtons(container)[0];
if (!rerunBtn) throw new Error('rerun button missing');
rerunBtn.disabled = false;
rerunBtn.click();
await new Promise((r) => setTimeout(r, 800));
const lastCheck = container.querySelector('[data-testid="diagnostics-last-check"]')?.textContent ?? '';
const staleBanner = container.querySelector('[data-testid="diagnostics-banner-title"]');
const stillShowsRows = container.querySelector('[data-testid="diagnostics-row-router"]') !== null;
dispose();
console.log(JSON.stringify({{
  staleMarked: lastCheck.includes('устарели') || lastCheck.includes('успешная'),
  stillShowsRows,
  staleBannerHidden: staleBanner === null,
  healthCalls: call,
}}));
""",
    )
    assert result["healthCalls"] >= 2
    assert result["staleMarked"] is True
    assert result["stillShowsRows"] is True
    assert result["staleBannerHidden"] is True


def test_diagnostics_run_aborts_on_first_401(tmp_path: Path) -> None:
    """F-6: первый 401 прерывает остальные запросы прогона."""
    errors_uri = json.dumps((HUB / "core" / "errors.js").as_uri())
    result = _run_model_export(
        tmp_path,
        label="auth-abort-run",
        script_body=f"""
import {{ HubApiError, ERROR_KIND }} from {errors_uri};

let unauthorizedCalls = 0;
let parallelStarts = 0;
globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const u = String(url);
  if (method === 'POST' && u.includes('/lab/connection-health')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{
      status: 'green', reason_code: 'all_facts_healthy',
      facts: {{ reachable: true, host_key_match: true, tuple_match: true, credentials_present: true, evidence_fresh: true }},
    }}) }};
  }}
  if (method === 'POST' && (u.includes('/lab/host-internet-probe') || u.includes('/wifi/observed-state') || u.includes('/entry-pages') || u.includes('/event-presets'))) {{
    parallelStarts += 1;
    if (u.includes('/lab/host-internet-probe')) {{
      unauthorizedCalls += 1;
      return {{ ok: false, status: 401, headers: {{ get: () => 'application/json' }}, json: async () => ({{ detail: 'auth' }}) }};
    }}
    await new Promise((r) => setTimeout(r, 50));
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
  }}
  if (method === 'GET' && u.includes('/entry-pages')) {{
    return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{ items: [] }}) }};
  }}
  return {{ ok: true, status: 200, headers: {{ get: () => 'application/json' }}, json: async () => ({{}}) }};
}};

let caught = null;
try {{
  await mod.runDiagnosticsChecks({{
    session: {{ routerId: 'r1', hostKeyConfirmed: true, wifiRoles: {{ staffApId: 'ap1', guestApId: 'ap2' }}, eventPresetId: 'preset-1' }},
    adapterMode: 'live',
    hostKeyConfirmed: true,
    routerPresent: true,
    routerId: 'r1',
  }});
}} catch (err) {{
  caught = {{ kind: err.kind ?? null, name: err.name ?? null }};
}}

console.log(JSON.stringify({{ unauthorizedCalls, caught, parallelStarts }}));
""",
    )
    assert result["unauthorizedCalls"] == 1
    assert result["caught"] is not None
    assert result["caught"]["kind"] == "UNAUTHORIZED"


def test_captive_portal_note_single_definition() -> None:
    """F-9: одна формулировка captive/auto-open unsupported."""
    entry_source = _read(HUB / "features" / "entry-pages-model.js")
    diag_source = _read(DIAG_MODEL_JS)
    assert "export const ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE" in entry_source
    assert "ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE" in diag_source
    assert entry_source.count("Принудительное автооткрытие страницы после подключения к Wi‑Fi") == 1
    assert "Captive portal" not in diag_source


def _collect_user_string_literals(source: str) -> list[str]:
    literals = re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", source)
    literals += re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', source)
    for match in re.finditer(r"`([^`]*)`", source):
        static = re.sub(r"\$\{[^}]*\}", "", match.group(1))
        if static:
            literals.append(static)
    return literals


def test_diagnostics_user_strings_no_jargon() -> None:
    """F-8: jargon scanner covers template literals too."""
    combined = _read(DIAG_SCREEN_JS) + "\n" + _read(DIAG_MODEL_JS)
    forbidden = (
        "read-only API",
        "captive portal",
        "reason_code",
        "provableState",
    )
    for literal in _collect_user_string_literals(combined):
        if not re.search(r"[\u0400-\u04FF]", literal):
            continue
        for jargon in forbidden:
            assert jargon not in literal, f"jargon {jargon!r} in: {literal!r}"


def test_diagnostics_model_blocks_success_while_rows_loading(tmp_path: Path) -> None:
    """F-DIAG-02: mid-run assemble не выдаёт success при loading siblings."""
    result = _run_model_export(
        tmp_path,
        label="midrun-success-block",
        script_body="""
const rows = [
  mod.buildRouterRowFromVerdict({
    level: 'READY',
    hubState: 'SUCCESS',
    title: 'ok',
    description: 'ok',
    badgeLabel: 'ok',
    badgeTone: 'success',
    reasonCode: 'all_facts_healthy',
    facts: [],
    host: null,
    routerId: 'r1',
    mock: false,
    mockNote: null,
    checkedAt: new Date(),
  }, { adapterMode: 'live' }),
  mod.buildWifiRowFromObserved(null, { title: 'Рабочая сеть', apId: 'ap1', loading: true }),
];
const snapshot = mod.assembleDiagnosticsSnapshot({
  rows,
  systemVerdict: {
    level: 'READY',
    hubState: 'SUCCESS',
    title: 'ok',
    description: 'ok',
    badgeLabel: 'ok',
    badgeTone: 'success',
    reasonCode: 'all_facts_healthy',
    facts: [],
    host: null,
    routerId: 'r1',
    mock: false,
    mockNote: null,
    checkedAt: new Date(),
  },
  checkedAt: new Date(),
  runComplete: false,
}, 'live');
console.log(JSON.stringify({
  bannerTone: snapshot.bannerTone,
  hasLoading: mod.hasLoadingDiagnosticRows(rows),
  checkedAt: snapshot.checkedAt,
}));
""",
    )
    assert result["hasLoading"] is True
    assert result["bannerTone"] != "success"
    assert result["checkedAt"] is None


def test_diagnostics_screen_on_progress_and_export_gate() -> None:
    """F-DIAG-01/02: onProgress в screen; export gated by running + checkedAt."""
    source = _read(DIAG_SCREEN_JS)
    assert "onProgress" in source
    assert "lastSummarySignature" in source
    assert "canExportReport(snapshot, running)" in source


def test_diagnostics_subscribe_connectivity_inverts_online_flag() -> None:
    """F-4: subscribeConnectivity получает online; offline = !online."""
    source = _read(DIAG_SCREEN_JS)
    assert "subscribeConnectivity((online)" in source
    assert "offline = !online" in source
    assert "offline = nextOffline" not in source


def test_diagnostics_rebuild_slot_preserves_scroll_and_focus() -> None:
    """F-5: rebuildSlot сохраняет scroll/focus как на vpn/entry экранах."""
    source = _read(DIAG_SCREEN_JS)
    rebuild_body = _extract_function_body(source, "function rebuildSlot(slot, rebuild)")
    assert rebuild_body is not None
    assert "captureHubContentScroll" in rebuild_body
    assert "restoreHubContentScroll" in rebuild_body
    assert "restorePendingFocus" in rebuild_body
    assert "pendingFocus" in rebuild_body


def test_diagnostics_start_run_hides_stale_success_while_running() -> None:
    """F-6: повторный startRun не показывает прошлый success banner до onProgress."""
    source = _read(DIAG_SCREEN_JS)
    assert "running && snapshot" in source
    assert "running-stale" in source
    summary_body = _extract_function_body(source, "function renderSummarySlot()")
    assert summary_body is not None
    assert summary_body.count("running && snapshot") >= 1


def test_diagnostics_stale_abort_catch_does_not_clear_running() -> None:
    """F-7: aborted/stale catch must not assign running=false; newer run owns running."""
    source = _read(DIAG_SCREEN_JS)
    start_run_body = _extract_function_body(source, "async function startRun()")
    assert start_run_body is not None

    assert re.search(
        r"if \(disposed \|\| !shouldAcceptDiagnosticsGeneration\(myGeneration, runGeneration\)\) \{\s*return;\s*\}",
        start_run_body,
    )

    assert (
        "if (disposed || isAborted(err) || !shouldAcceptDiagnosticsGeneration(myGeneration, runGeneration))"
        not in start_run_body
    )

    catch_start = start_run_body.find("} catch (err) {")
    assert catch_start != -1
    catch_body = start_run_body[catch_start:]

    assert re.search(
        r"if \(disposed\) \{\s*running = false;\s*return;\s*\}",
        catch_body,
    )

    stale_branch = re.search(
        r"if \(isAborted\(err\) \|\| !shouldAcceptDiagnosticsGeneration\(myGeneration, runGeneration\)\) \{(.*?)\}",
        catch_body,
        re.DOTALL,
    )
    assert stale_branch is not None
    assert "running = false" not in stale_branch.group(1)
