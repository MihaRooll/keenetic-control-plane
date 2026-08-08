"""Поведенческие контракты модели экрана «Домен» LOCAL HUB."""

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
DOMAIN_MODEL_JS = HUB / "features" / "domain-model.js"
DOMAIN_SIMPLE_PUBLISH_JS = HUB / "features" / "domain-simple-publish.js"
DOMAIN_SCREEN_JS = HUB / "screens" / "domain.js"
OVERVIEW_JS = HUB / "screens" / "overview.js"
UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

FORBIDDEN_DOMAIN_LITERALS = (
    "Приложение опубликовано",
    "Сертификат действителен",
    "Переадресация работает",
    "После изменения адреса старая ссылка перестанет работать",
)

FORBIDDEN_DOMAIN_BADGE_RE = re.compile(
    r"""(?:label|title):\s*['"]Доступно['"]""",
)

FORBIDDEN_KEENDNS_DISPATCH_PATHS = (
    "keendns/book",
    "keendns/drop",
    "keendns/update",
)

ALLOWED_KEENDNS_PATHS = (
    "keendns/status",
    "keendns/preview",
    "keendns/apply",
)

HOST_HTTP_UNKNOWN_REASON_CODES = (
    "host_http.pending",
    "host_http.unparseable_url",
    "host_http.url_not_allowed",
    "host_http.dns_failed",
    "host_http.dns_unavailable",
    "host_http.dns_timeout",
    "host_http.target_address_not_allowed",
    "host_http.timeout",
    "host_http.redirect_not_followed",
    "host_http.unexpected_status",
    "host_http.unreachable",
    "host_http.preset_not_found",
    "host_http.failed",
)

HOST_TLS_UNKNOWN_REASON_CODES = (
    "host_tls.pending",
    "host_tls.hostname_not_allowed",
    "host_tls.dns_failed",
    "host_tls.dns_unavailable",
    "host_tls.dns_timeout",
    "host_tls.target_address_not_allowed",
    "host_tls.unreachable",
    "host_tls.no_certificate",
    "host_tls.partial",
    "host_tls.preset_not_found",
    "host_tls.failed",
)

HOST_INTERNET_UNKNOWN_REASON_CODES = (
    "host_internet.pending",
    "host_internet.dns_unavailable",
    "host_internet.dns_failed",
    "host_internet.no_route",
    "host_internet.inconclusive",
    "host_internet.failed",
)

HOST_PROBES_PY = REPO_ROOT / "router_control_host" / "host_probes.py"
HOST_PROBE_REASON_CODE_RE = re.compile(r'"(host_(?:http|tls|internet)\.[a-z_]+)"')
GENERIC_HOST_PROBE_MESSAGE = "Результат проверки неизвестен."

HOST_HTTP_REFUTED_REASON_CODES = frozenset(
    {
        "host_http.http_error",
        "host_http.connection_refused",
    },
)

HOST_TLS_REFUTED_REASON_CODES = frozenset(
    {
        "host_tls.certificate_expired",
        "host_tls.hostname_mismatch",
    },
)

HOST_INTERNET_REFUTED_REASON_CODES = frozenset({"host_internet.offline_or_unreachable"})

OPERATOR_SCOPE_MARKERS = (
    "оператора",
    "с компьютера оператора",
)

CYRILLIC = re.compile(r"[А-Яа-яЁё]")

FORBIDDEN_DOMAIN_OPERATOR_JARGON = (
    "KeenDNS",
    "accept-list",
    "AccessPoint",
    "WifiMaster",
    "RCI",
    "Uplink",
    "Station",
    "классификатор",
    "ndns",
)


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            f"node is required for hub domain tests; install Node.js or set "
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


def _run_export(
    tmp_path: Path,
    *,
    label: str,
    script_body: str,
    model_source: str | None = None,
) -> object:
    if model_source is None:
        model_uri = DOMAIN_MODEL_JS.as_uri()
    else:
        model_copy = tmp_path / f"{label}-domain-model.mjs"
        model_copy.parent.mkdir(parents=True, exist_ok=True)
        model_copy.write_text(model_source, encoding="utf-8")
        model_uri = model_copy.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def _collect_host_probe_reason_codes_from_backend() -> frozenset[str]:
    source = HOST_PROBES_PY.read_text(encoding="utf-8")
    codes = frozenset(HOST_PROBE_REASON_CODE_RE.findall(source))
    assert len(codes) >= 30, (
        f"expected at least 30 host probe reason codes from {HOST_PROBES_PY.name}, "
        f"got {len(codes)}: {sorted(codes)}"
    )
    return codes


def _describe_fn_for_reason_code(reason_code: str) -> str:
    if reason_code.startswith("host_http."):
        return "describeHostHttpProbe"
    if reason_code.startswith("host_tls."):
        return "describeHostTlsProbe"
    return "describeHostInternetProbe"


def _backend_payload_for_reason_code(reason_code: str) -> dict[str, object]:
    payload: dict[str, object] = {"reason_code": reason_code}
    if reason_code.startswith("host_http."):
        if reason_code == "host_http.reachable":
            payload["reachable"] = True
        elif reason_code in HOST_HTTP_REFUTED_REASON_CODES:
            payload["reachable"] = False
        else:
            payload["reachable"] = None
        return payload
    if reason_code.startswith("host_tls."):
        if reason_code == "host_tls.ok":
            payload["aggregate_status"] = "ok"
        elif reason_code in HOST_TLS_REFUTED_REASON_CODES:
            payload["aggregate_status"] = "failed"
        elif reason_code in ("host_tls.untrusted_issuer", "host_tls.partial"):
            payload["aggregate_status"] = "warning"
        else:
            payload["aggregate_status"] = "unknown"
        return payload
    if reason_code == "host_internet.reachable":
        payload["internet_reachable"] = True
    elif reason_code in HOST_INTERNET_REFUTED_REASON_CODES:
        payload["internet_reachable"] = False
    else:
        payload["internet_reachable"] = None
    return payload


@pytest.mark.parametrize(
    "status_payload",
    [
        {
            "feature_availability": "unknown",
            "name_reservation": "unknown",
            "access_mode": "unknown",
        },
        {"feature_availability": "unavailable"},
        {
            "feature_availability": "available",
            "name_reservation": "reserved",
            "access_mode": "cloud",
        },
        {},
        None,
    ],
)
def test_domain_describe_keendns_status_never_success(
    tmp_path: Path,
    status_payload: dict[str, str] | None,
) -> None:
    """D-DOM-1: describeKeendnsStatus никогда не возвращает HubState.SUCCESS."""
    payload_json = "null" if status_payload is None else json.dumps(status_payload)
    result = _run_export(
        tmp_path,
        label="keendns-status",
        script_body=f"""
console.log(JSON.stringify(mod.describeKeendnsStatus({payload_json})));
""",
    )
    assert result["hubState"] != "SUCCESS"


@pytest.mark.parametrize(
    "preview_payload",
    [
        {"verification_status": "documentation_sourced_unconfirmed", "preview_ops": []},
        {
            "verification_status": "confirmed",
            "preview_ops": [{"command_text": "ndns book-name demo keenetic.pro auto"}],
        },
        {},
        None,
    ],
)
def test_domain_describe_preview_never_success(
    tmp_path: Path,
    preview_payload: dict[str, object] | None,
) -> None:
    """D-DOM-1: describePreview никогда не возвращает HubState.SUCCESS."""
    payload_json = "null" if preview_payload is None else json.dumps(preview_payload)
    result = _run_export(
        tmp_path,
        label="preview",
        script_body=f"""
console.log(JSON.stringify(mod.describePreview({payload_json})));
""",
    )
    assert result["hubState"] != "SUCCESS"


def test_domain_forbidden_publication_literals_absent_from_model_and_screen() -> None:
    """D-DOM-1/D-DOM-12: запрещённые формулировки макета отсутствуют в модели и экране."""
    combined = (
        DOMAIN_MODEL_JS.read_text(encoding="utf-8")
        + DOMAIN_SCREEN_JS.read_text(encoding="utf-8")
        + DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")
    )
    for literal in FORBIDDEN_DOMAIN_LITERALS:
        assert literal not in combined, f"forbidden literal: {literal}"
    assert FORBIDDEN_DOMAIN_BADGE_RE.search(combined) is None


def test_domain_success_only_from_operator_host_probes(tmp_path: Path) -> None:
    """D-DOM-2: SUCCESS модели — только host-side пробы с fact=true и областью «оператора»."""
    result = _run_export(
        tmp_path,
        label="success-inventory",
        script_body="""
const cases = [
  mod.describeHostHttpProbe({ reachable: true, reason_code: 'host_http.reachable' }),
  mod.describeHostInternetProbe({
    internet_reachable: true,
    reason_code: 'host_internet.reachable',
  }),
  mod.describeHostTlsProbe({
    aggregate_status: 'ok',
    reason_code: 'host_tls.ok',
    chain_inspected: false,
  }),
  mod.describeKeendnsStatus({
    feature_availability: 'unknown',
    name_reservation: 'unknown',
    access_mode: 'unknown',
  }),
  mod.describePreview({ verification_status: 'documentation_sourced_unconfirmed' }),
];
console.log(JSON.stringify(cases.map((item) => ({
  hubState: item.hubState,
  title: item.title,
  factState: item.factState ?? null,
}))));
""",
    )
    success_rows = [row for row in result if row["hubState"] == "SUCCESS"]
    assert len(success_rows) == 3
    for row in success_rows:
        title_lower = row["title"].lower()
        assert any(marker in title_lower for marker in ("оператора", "с компьютера оператора"))
        assert row["factState"] == "confirmed"


def test_domain_keendns_status_request_body_empty(tmp_path: Path) -> None:
    """D-DOM-3: POST keendns/status отправляет пустое тело {}."""
    result = _run_export(
        tmp_path,
        label="status-body",
        script_body="""
const captured = { body: null, path: null };
globalThis.fetch = async (url, init) => {
  captured.path = String(url);
  captured.body = init?.body ?? null;
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => ({
      feature_availability: 'unknown',
      name_reservation: 'unknown',
      access_mode: 'unknown',
    }),
  };
};
await mod.loadKeendnsStatus();
console.log(JSON.stringify(captured));
""",
    )
    assert result["body"] == "{}"
    assert "keendns/status" in result["path"]


def test_domain_all_unknown_status_renders_unknown_message(tmp_path: Path) -> None:
    """D-DOM-3: all-unknown ответ классификатора → честное «неизвестно», не SUCCESS."""
    result = _run_export(
        tmp_path,
        label="all-unknown",
        script_body="""
const described = mod.describeKeendnsStatus({
  feature_availability: 'unknown',
  name_reservation: 'unknown',
  access_mode: 'unknown',
});
console.log(JSON.stringify({
  hubState: described.hubState,
  title: described.title,
  message: described.message,
}));
""",
    )
    assert result["hubState"] == "WARNING"
    assert result["hubState"] != "SUCCESS"
    assert result["title"] == "Публикация в облаке не выполнена"
    assert "неизвест" in result["message"].lower() or "не проверя" in result["message"].lower()


def test_domain_operator_prose_simple_russian_no_jargon(tmp_path: Path) -> None:
    """Видимый текст «Домен» — простой русский без KeenDNS/accept-list и прочего жаргона."""
    screen_source = DOMAIN_SCREEN_JS.read_text(encoding="utf-8")
    model_source = DOMAIN_MODEL_JS.read_text(encoding="utf-8")

    note_match = re.search(r"const KEENDNS_NO_CONFIG_NOTE\s*=\s*\n?\s*'([^']+)'", screen_source)
    assert note_match is not None
    note_text = note_match.group(1)
    assert CYRILLIC.search(note_text)
    for forbidden in FORBIDDEN_DOMAIN_OPERATOR_JARGON:
        assert forbidden not in note_text, f"{forbidden!r} in KEENDNS_NO_CONFIG_NOTE"

    for source_path, source in (
        (DOMAIN_SCREEN_JS, screen_source),
        (DOMAIN_MODEL_JS, model_source),
        (DOMAIN_SIMPLE_PUBLISH_JS, DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")),
    ):
        literals = re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", source)
        literals += re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', source)
        for literal in literals:
            if not CYRILLIC.search(literal):
                continue
            for forbidden in FORBIDDEN_DOMAIN_OPERATOR_JARGON:
                assert forbidden not in literal, (
                    f"jargon {forbidden!r} in {source_path.name}: {literal!r}"
                )

    result = _run_export(
        tmp_path,
        label="domain-jargon-status",
        script_body="""
const unavailable = mod.describeKeendnsStatus({ feature_availability: 'unavailable' });
const allUnknown = mod.describeKeendnsStatus({
  feature_availability: 'unknown',
  name_reservation: 'unknown',
  access_mode: 'unknown',
});
const publish = mod.buildPublishRequestSummary({
  name: 'demo',
  domain: 'keenetic.pro',
  mode: 'auto',
});
console.log(JSON.stringify({
  unavailableMessage: unavailable.message,
  allUnknownMessage: allUnknown.message,
  publishSummary: publish,
}));
""",
    )
    for key in ("unavailableMessage", "allUnknownMessage"):
        text = result[key]
        for forbidden in FORBIDDEN_DOMAIN_OPERATOR_JARGON:
            assert forbidden not in text, f"{forbidden!r} in {key}: {text!r}"

    checklist_started = False
    for line in result["publishSummary"].split("\n"):
        if line.startswith("Что должен подтвердить"):
            checklist_started = True
        if not checklist_started:
            continue
        if line.startswith("ndns "):
            continue
        for forbidden in ("KeenDNS", "accept-list", "классификатор", "ndns"):
            assert forbidden not in line, f"{forbidden!r} in checklist line: {line!r}"


def test_domain_save_local_order_url_preserves_document_keys(tmp_path: Path) -> None:
    """D-DOM-5: saveLocalOrderUrl — If-Match пресета, Idempotency-Key, полный document."""
    original_document = {
        "local_order_url": "https://orders.booth.local/",
        "event_name": "Demo Event",
        "venue_code": "hall-a",
        "notes": "keep-me",
    }
    preset_etag = '"preset-etag-7"'
    revision_etag = '"revision-etag-9"'
    new_url = "https://orders.booth.local:8443/app"
    result = _run_export(
        tmp_path,
        label="save-local-order",
        script_body=f"""
const original = {json.dumps(original_document, ensure_ascii=False)};
const captured = {{ headers: {{}}, body: null, path: null }};
globalThis.fetch = async (url, init) => {{
  captured.path = String(url);
  captured.headers = Object.fromEntries(new Headers(init.headers).entries());
  captured.body = JSON.parse(init.body);
  return {{
    ok: true,
    status: 200,
    headers: {{ get: () => 'application/json' }},
    json: async () => ({{ ok: true }}),
  }};
}};
await mod.saveLocalOrderUrl({{
  presetId: 'preset-1',
  revisionId: 'rev-1',
  document: original,
  localOrderUrl: {json.dumps(new_url)},
  etag: {json.dumps(preset_etag)},
  idempotencyKey: 'idem-domain-test-1',
}});
const sentDoc = captured.body.document;
console.log(JSON.stringify({{
  ifMatch: captured.headers['If-Match'] ?? captured.headers['if-match'] ?? null,
  idempotencyKey:
    captured.headers['Idempotency-Key'] ?? captured.headers['idempotency-key'] ?? null,
  originalKeys: Object.keys(original).sort(),
  sentKeys: Object.keys(sentDoc).sort(),
  onlyLocalOrderUrlChanged:
    Object.keys(original).every((key) => key === 'local_order_url'
      ? sentDoc[key] === {json.dumps(new_url)}
      : sentDoc[key] === original[key]),
  revisionEtagUsed: captured.headers['If-Match'] === {json.dumps(revision_etag)},
}}));
""",
    )
    assert result["ifMatch"] == preset_etag
    assert result["revisionEtagUsed"] is False
    assert result["idempotencyKey"] == "idem-domain-test-1"
    assert result["originalKeys"] == result["sentKeys"]
    assert result["onlyLocalOrderUrlChanged"] is True


@pytest.mark.parametrize(
    ("raw_name", "expected_url"),
    [
        ("demo", "https://demo.keenetic.pro"),
        ("a-b", "https://a-b.keenetic.pro"),
        ("a1", "https://a1.keenetic.pro"),
    ],
)
def test_domain_validate_and_build_draft_url_valid(
    tmp_path: Path,
    raw_name: str,
    expected_url: str,
) -> None:
    """D-DOM-6: корректные метки DNS → URL черновика."""
    result = _run_export(
        tmp_path,
        label=f"valid-{raw_name}",
        script_body=f"""
const validation = mod.validateDomainName({json.dumps(raw_name)});
const url = mod.buildDraftUrl({{ name: {json.dumps(raw_name)}, domain: 'keenetic.pro' }});
console.log(JSON.stringify({{ validation, url }}));
""",
    )
    assert result["validation"]["valid"] is True
    assert result["url"] == expected_url


@pytest.mark.parametrize(
    "raw_name",
    [
        "",
        "bad_name",
        "-leading",
        "trailing-",
        "a" * 64,
        "label.with.dot",
    ],
)
def test_domain_validate_and_build_draft_url_invalid(
    tmp_path: Path,
    raw_name: str,
) -> None:
    """D-DOM-6: некорректные метки → null URL."""
    result = _run_export(
        tmp_path,
        label=f"invalid-{abs(hash(raw_name))}",
        script_body=f"""
const validation = mod.validateDomainName({json.dumps(raw_name)});
const url = mod.buildDraftUrl({{ name: {json.dumps(raw_name)}, domain: 'keenetic.pro' }});
console.log(JSON.stringify({{ validation, url }}));
""",
    )
    assert result["validation"]["valid"] is False
    assert result["url"] is None


def test_domain_validate_normalizes_uppercase_input(tmp_path: Path) -> None:
    """D-DOM-6: регистр приводится к нижнему — UPPER даёт URL с lower label."""
    result = _run_export(
        tmp_path,
        label="upper-normalize",
        script_body="""
const validation = mod.validateDomainName('UPPER');
const url = mod.buildDraftUrl({ name: 'UPPER', domain: 'keenetic.pro' });
console.log(JSON.stringify({ validation, url }));
""",
    )
    assert result["validation"]["valid"] is True
    assert result["url"] == "https://upper.keenetic.pro"


def test_domain_keendns_paths_allowed_and_dispatch_forbidden() -> None:
    """D-DOM-7: keendns/status, preview, apply; без book/drop/update путей."""
    combined = DOMAIN_MODEL_JS.read_text(encoding="utf-8") + DOMAIN_SCREEN_JS.read_text(
        encoding="utf-8",
    )
    for path in ALLOWED_KEENDNS_PATHS:
        assert path in combined, f"missing allowed path: {path}"
    for forbidden in FORBIDDEN_KEENDNS_DISPATCH_PATHS:
        assert forbidden not in combined, f"forbidden dispatch path: {forbidden}"


PROBE_FACT_MATRIX: tuple[tuple[dict[str, object], str, str | None], ...] = (
    (
        {
            "fn": "describeHostHttpProbe",
            "payload": {"reachable": True, "reason_code": "host_http.reachable"},
        },
        "confirmed",
        None,
    ),
    (
        {
            "fn": "describeHostHttpProbe",
            "payload": {
                "reachable": False,
                "reason_code": "host_http.connection_refused",
            },
        },
        "refuted",
        None,
    ),
    (
        {
            "fn": "describeHostHttpProbe",
            "payload": {"reachable": None, "reason_code": "host_http.timeout"},
        },
        "unknown",
        "refuted",
    ),
    (
        {
            "fn": "describeHostHttpProbe",
            "payload": {
                "reachable": False,
                "reason_code": "host_http.target_address_not_allowed",
            },
        },
        "unknown",
        "refuted",
    ),
    (
        {
            "fn": "describeHostHttpProbe",
            "payload": {"reachable": None, "reason_code": "host_http.dns_failed"},
        },
        "unknown",
        "refuted",
    ),
    (
        {
            "fn": "describeHostTlsProbe",
            "payload": {"aggregate_status": "ok", "reason_code": "host_tls.ok"},
        },
        "confirmed",
        None,
    ),
    (
        {
            "fn": "describeHostTlsProbe",
            "payload": {
                "aggregate_status": "failed",
                "reason_code": "host_tls.hostname_mismatch",
            },
        },
        "refuted",
        None,
    ),
    (
        {
            "fn": "describeHostTlsProbe",
            "payload": {
                "aggregate_status": "unknown",
                "reason_code": "host_tls.partial",
            },
        },
        "unknown",
        "refuted",
    ),
    (
        {
            "fn": "describeHostTlsProbe",
            "payload": {"reason_code": "host_tls.target_address_not_allowed"},
        },
        "unknown",
        "refuted",
    ),
    (
        {
            "fn": "describeHostInternetProbe",
            "payload": {
                "internet_reachable": True,
                "reason_code": "host_internet.reachable",
            },
        },
        "confirmed",
        None,
    ),
    (
        {
            "fn": "describeHostInternetProbe",
            "payload": {
                "internet_reachable": False,
                "reason_code": "host_internet.offline_or_unreachable",
            },
        },
        "refuted",
        None,
    ),
    (
        {
            "fn": "describeHostInternetProbe",
            "payload": {"reason_code": "host_internet.dns_failed"},
        },
        "unknown",
        "refuted",
    ),
)


@pytest.mark.parametrize(
    ("described", "expected_fact_state", "forbidden_fact_state"),
    PROBE_FACT_MATRIX,
)
def test_domain_probe_fact_state_matrix(
    tmp_path: Path,
    described: dict[str, object],
    expected_fact_state: str,
    forbidden_fact_state: str | None,
) -> None:
    """D-DOM-9: true/false/null+reason → confirmed/refuted/unknown; отказ/таймаут/DNS не refuted."""
    fn_name = str(described["fn"])
    payload_json = json.dumps(described["payload"], ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label=f"matrix-{fn_name}-{expected_fact_state}",
        script_body=f"""
const described = mod.{fn_name}({payload_json});
console.log(JSON.stringify({{ factState: described.factState, hubState: described.hubState }}));
""",
    )
    assert result["factState"] == expected_fact_state
    if forbidden_fact_state is not None:
        assert result["factState"] != forbidden_fact_state


@pytest.mark.parametrize("reason_code", HOST_HTTP_UNKNOWN_REASON_CODES)
def test_domain_http_probe_unknown_reason_codes_never_refuted(
    tmp_path: Path,
    reason_code: str,
) -> None:
    """D-DOM-9: коды неопределённости HTTP-пробы не классифицируются как refuted."""
    if reason_code == "host_http.target_address_not_allowed":
        payload = {"reason_code": reason_code, "reachable": False}
    else:
        payload = {"reason_code": reason_code, "reachable": None}
    result = _run_export(
        tmp_path,
        label=f"http-unknown-{reason_code}",
        script_body=f"""
console.log(JSON.stringify(mod.describeHostHttpProbe({json.dumps(payload)})));
""",
    )
    assert result["factState"] == "unknown"
    assert result["factState"] != "refuted"


@pytest.mark.parametrize("reason_code", HOST_TLS_UNKNOWN_REASON_CODES)
def test_domain_tls_probe_unknown_reason_codes_never_refuted(
    tmp_path: Path,
    reason_code: str,
) -> None:
    """D-DOM-9: коды неопределённости TLS-пробы не классифицируются как refuted."""
    payload = {"reason_code": reason_code, "aggregate_status": "unknown"}
    result = _run_export(
        tmp_path,
        label=f"tls-unknown-{reason_code}",
        script_body=f"""
console.log(JSON.stringify(mod.describeHostTlsProbe({json.dumps(payload)})));
""",
    )
    assert result["factState"] == "unknown"
    assert result["factState"] != "refuted"


@pytest.mark.parametrize("reason_code", HOST_INTERNET_UNKNOWN_REASON_CODES)
def test_domain_internet_probe_unknown_reason_codes_never_refuted(
    tmp_path: Path,
    reason_code: str,
) -> None:
    """D-DOM-9: коды неопределённости internet-пробы не классифицируются как refuted."""
    result = _run_export(
        tmp_path,
        label=f"internet-unknown-{reason_code}",
        script_body=f"""
console.log(JSON.stringify(mod.describeHostInternetProbe({{
  reason_code: {json.dumps(reason_code)},
}})));
""",
    )
    assert result["factState"] == "unknown"
    assert result["factState"] != "refuted"


@pytest.mark.parametrize(
    "aggregate_status",
    ["warning", "unknown"],
)
def test_domain_tls_warning_or_unknown_never_success(
    tmp_path: Path,
    aggregate_status: str,
) -> None:
    """D-DOM-10: aggregate_status warning/unknown не даёт положительного вердикта."""
    result = _run_export(
        tmp_path,
        label=f"tls-{aggregate_status}",
        script_body=f"""
console.log(JSON.stringify(mod.describeHostTlsProbe({{
  aggregate_status: {json.dumps(aggregate_status)},
  reason_code: 'host_tls.untrusted_issuer',
}})));
""",
    )
    assert result["hubState"] != "SUCCESS"
    assert result["factState"] == "unknown"


def test_domain_model_syntax_via_mjs_copy(tmp_path: Path) -> None:
    """Синтаксис domain-model.js проверяется копией .mjs."""
    node = _require_node()
    mjs_copy = tmp_path / "domain-model.mjs"
    mjs_copy.write_text(DOMAIN_MODEL_JS.read_text(encoding="utf-8"), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_domain_model_no_blob_or_create_object_url() -> None:
    """D-DOM-11: модель не использует blob: или createObjectURL."""
    source = DOMAIN_MODEL_JS.read_text(encoding="utf-8")
    assert "blob:" not in source
    assert "createObjectURL" not in source


def test_domain_host_probe_reason_codes_synced_with_backend(tmp_path: Path) -> None:
    """D-DOM-9: reason_code из host_probes.py → русское сообщение, не generic fallback."""
    backend_codes = sorted(_collect_host_probe_reason_codes_from_backend())
    cases = [
        (_describe_fn_for_reason_code(code), _backend_payload_for_reason_code(code))
        for code in backend_codes
    ]
    cases_json = json.dumps(cases, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="host-probe-reason-sync",
        script_body=f"""
const generic = {json.dumps(GENERIC_HOST_PROBE_MESSAGE)};
const cases = {cases_json};
const rows = cases.map(([fnName, payload]) => {{
  const described = mod[fnName](payload);
  return {{
    reasonCode: payload.reason_code,
    message: described.message,
    isGeneric: described.message === generic,
  }};
}});
console.log(JSON.stringify(rows));
""",
    )
    generic_codes = [row["reasonCode"] for row in result if row["isGeneric"]]
    assert not generic_codes, (
        "host probe reason codes without Russian mapping "
        f"(generic fallback): {generic_codes}"
    )


def test_domain_host_probe_reason_codes_fact_state_honest(tmp_path: Path) -> None:
    """D-DOM-9: factState refuted только когда backend-факт действительно false."""
    backend_codes = sorted(_collect_host_probe_reason_codes_from_backend())
    refuted_codes = (
        HOST_HTTP_REFUTED_REASON_CODES
        | HOST_TLS_REFUTED_REASON_CODES
        | HOST_INTERNET_REFUTED_REASON_CODES
    )
    cases = [
        (_describe_fn_for_reason_code(code), _backend_payload_for_reason_code(code))
        for code in backend_codes
    ]
    cases_json = json.dumps(cases, ensure_ascii=False)
    refuted_json = json.dumps(sorted(refuted_codes))
    result = _run_export(
        tmp_path,
        label="host-probe-fact-state",
        script_body=f"""
const refutedCodes = new Set({refuted_json});
const cases = {cases_json};
const rows = cases.map(([fnName, payload]) => {{
  const described = mod[fnName](payload);
  return {{
    reasonCode: payload.reason_code,
    factState: described.factState,
    expectsRefuted: refutedCodes.has(payload.reason_code),
  }};
}});
console.log(JSON.stringify(rows));
""",
    )
    violations = [
        row
        for row in result
        if row["factState"] == "refuted" and not row["expectsRefuted"]
    ]
    assert not violations, (
        "factState refuted for codes without backend false fact: "
        f"{[row['reasonCode'] for row in violations]}"
    )
    missing_refuted = [
        row["reasonCode"]
        for row in result
        if row["expectsRefuted"] and row["factState"] != "refuted"
    ]
    assert not missing_refuted, (
        "expected refuted factState for backend false facts: "
        f"{missing_refuted}"
    )


def test_domain_simple_publish_module_exports(tmp_path: Path) -> None:
    """R-8: reusable mount + apply confirm helper exported from domain-simple-publish.js."""
    simple_uri = DOMAIN_SIMPLE_PUBLISH_JS.as_uri()
    result = _run_node_harness(
        f"""
const mod = await import({json.dumps(simple_uri)});
console.log(JSON.stringify({{
  mount: typeof mod.mountDomainSimplePublishAffordance,
  applyConfirm: typeof mod.openDomainPublishApplyConfirm,
  gate: typeof mod.openDomainPublishHumanGate,
}}));
""",
        tmp_path,
        "simple-publish-exports",
    )
    assert result["mount"] == "function"
    assert result["applyConfirm"] == "function"
    assert result["gate"] == "function"


def test_domain_simple_publish_apply_confirm_catch_uses_describe_error() -> None:
    """hub-password-honesty: apply confirm catch routes errors through describeError."""
    source = DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")
    assert "describeError" in source.split("from '../core/errors.js';", 1)[0]
    catch_region = source.split("} catch (error) {", 1)[1].split("} finally {", 1)[0]
    assert "const described = describeError(error);" in catch_region
    assert "title: described.title" in catch_region
    assert "message: described.message" in catch_region
    assert "error.message" not in catch_region
    assert "error instanceof Error" not in catch_region


def test_domain_simple_default_name_and_honesty(tmp_path: Path) -> None:
    """R-8 AC-5: starter name promo + honesty constant; not host-persisted claim."""
    result = _run_export(
        tmp_path,
        label="simple-default",
        script_body="""
console.log(JSON.stringify({
  defaultName: mod.DOMAIN_SIMPLE_DEFAULT_NAME,
  resolved: mod.resolveDomainSimpleDefaultName(),
  honesty: mod.DOMAIN_SIMPLE_DEFAULT_NAME_HONESTY,
}));
""",
    )
    assert result["defaultName"] == "promo"
    assert result["resolved"] == "promo"
    assert "стартов" in result["honesty"].lower()
    assert "сохран" in result["honesty"].lower()


def test_domain_simple_name_state_format_ok_never_success(tmp_path: Path) -> None:
    """R-8 F-5: format-valid line is neutral — never HubState.SUCCESS or «Доступно»."""
    result = _run_export(
        tmp_path,
        label="simple-format-ok",
        script_body="""
const state = mod.describeDomainSimpleNameState({
  name: 'promo',
  domain: 'keenetic.pro',
});
console.log(JSON.stringify({
  valid: state.valid,
  formatMessage: state.formatMessage,
  availabilityMessage: state.availabilityMessage,
  formatOkConstant: mod.DOMAIN_SIMPLE_FORMAT_OK,
  draftUrl: state.draftUrl,
}));
""",
    )
    assert result["valid"] is True
    assert result["formatMessage"] == result["formatOkConstant"]
    assert result["formatMessage"] == "Формат имени подходит для черновика ссылки."
    assert "SUCCESS" not in json.dumps(result)
    assert "Доступно" not in result["formatMessage"]
    assert "неизвест" in result["availabilityMessage"].lower()
    assert result["draftUrl"] == "https://promo.keenetic.pro"


def test_domain_simple_publish_no_publication_claim_strings() -> None:
    """R-8 AC-3: apply path — CTA Опубликовать allowed; no live-proven success claims."""
    source = DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")
    forbidden = (
        "опубликовано",
        "зарегистрировано",
        "Приложение опубликовано",
    )
    for literal in forbidden:
        assert literal not in source, f"forbidden literal in simple publish: {literal}"
    assert "Опубликовать" in source
    assert "applyKeendnsBooking" not in source
    assert "keendns/apply" in DOMAIN_MODEL_JS.read_text(encoding="utf-8")


def test_domain_simple_publish_syntax_via_mjs_copy(tmp_path: Path) -> None:
    """Синтаксис domain-simple-publish.js проверяется копией .mjs."""
    node = _require_node()
    mjs_copy = tmp_path / "domain-simple-publish.mjs"
    mjs_copy.write_text(DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8"), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def _extract_function_body(source: str, signature: str) -> str | None:
    """Извлекает тело function по сигнатуре (пропускает `{` в параметрах)."""
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
                    c = source[j]
                    if c == "{":
                        body_depth += 1
                    elif c == "}":
                        body_depth -= 1
                        if body_depth == 0:
                            return source[brace + 1 : j]
                    j += 1
                return None
        i += 1
    return None


def test_domain_simple_publish_get_disabled_tracks_live_state(tmp_path: Path) -> None:
    """getDisabled flip + update() syncs CTA/inputs without remount (mount-time boolean close fails)."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    simple_uri = json.dumps(DOMAIN_SIMPLE_PUBLISH_JS.as_uri())
    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();

function patchElement(el) {{
  if (!el.getAttributeNames) {{
    el.getAttributeNames = () => Object.keys(el.attributes || {{}});
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

globalThis.document = dom.document;
const origCreateElement = dom.document.createElement.bind(dom.document);
dom.document.createElement = (tag) => patchElement(origCreateElement(tag));
dom.document.createElementNS = (_ns, tag) => patchElement(origCreateElement(tag));
dom.document.createTextNode = (text) => {{
  const node = patchElement(origCreateElement('span'));
  node.textContent = String(text ?? '');
  return node;
}};
dom.document.addEventListener = () => {{}};
dom.document.removeEventListener = () => {{}};

const sampleBtn = dom.document.createElement('button');
const sampleInput = dom.document.createElement('input');
globalThis.HTMLElement = sampleBtn.constructor;
globalThis.HTMLButtonElement = sampleBtn.constructor;
globalThis.HTMLInputElement = sampleInput.constructor;
globalThis.HTMLSelectElement = dom.document.createElement('select').constructor;
globalThis.HTMLTextAreaElement = dom.document.createElement('textarea').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});
globalThis.localStorage = dom.localStorage;
globalThis.window = {{
  ...dom.window,
  localStorage: dom.localStorage,
  open() {{ return null; }},
  addEventListener() {{}},
  removeEventListener() {{}},
  dispatchEvent() {{ return true; }},
}};
globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

const mod = await import({simple_uri});
const container = dom.document.createElement('div');
dom.document.body.appendChild(container);

let locked = true;
const mount = mod.mountDomainSimplePublishAffordance(container, {{
  getName: () => 'promo',
  setName: () => {{}},
  getDomain: () => 'netcraze.pro',
  setDomain: () => {{}},
  getDisabled: () => locked,
  onPublishApply: () => {{}},
  idPrefix: 'test-domain-simple',
}});

function publishDisabled() {{
  const btn = dom.document.getElementById('test-domain-simple-publish-btn');
  return Boolean(btn?.disabled);
}}
function nameInputDisabled() {{
  const input = dom.document.getElementById('test-domain-simple-name');
  return Boolean(input?.disabled);
}}

mount.update();
const whenLocked = {{ publish: publishDisabled(), name: nameInputDisabled() }};
locked = false;
mount.update();
const whenUnlocked = {{ publish: publishDisabled(), name: nameInputDisabled() }};
locked = true;
mount.update();
const lockedAgain = {{ publish: publishDisabled(), name: nameInputDisabled() }};

console.log(JSON.stringify({{ whenLocked, whenUnlocked, lockedAgain }}));
"""
    result = _run_node_harness(script, tmp_path, "simple-get-disabled-flip")
    assert result["whenLocked"]["publish"] is True
    assert result["whenLocked"]["name"] is True
    assert result["whenUnlocked"]["publish"] is False
    assert result["whenUnlocked"]["name"] is False
    assert result["lockedAgain"]["publish"] is True
    assert result["lockedAgain"]["name"] is True


def test_domain_screen_passes_get_disabled_to_simple_publish() -> None:
    """Domain screen mounts simple publish with live getDisabled (controlsLocked || offline)."""
    source = DOMAIN_SCREEN_JS.read_text(encoding="utf-8")
    mount_body = _extract_function_body(source, "function mountSimpleAffordanceInto(")
    assert mount_body is not None
    normalized = re.sub(r"\s+", " ", mount_body)
    assert "getDisabled: () => controlsLocked() || offline" in normalized
    assert "disabled: controlsLocked() || offline" not in normalized.replace(
        "getDisabled: () => controlsLocked() || offline",
        "",
    )


def test_domain_simple_publish_apply_toast_uses_danger_not_error() -> None:
    """KeenDNS publish fail toast uses toast-whitelist tone danger (not error→neutral)."""
    source = DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")
    assert "tone: 'error'" not in source
    confirm_body = _extract_function_body(source, "export function openDomainPublishApplyConfirm(")
    assert confirm_body is not None
    assert confirm_body.count("tone: 'danger'") >= 2


def test_domain_describe_keendns_apply_outcome_dispatched_offline(tmp_path: Path) -> None:
    """dispatched_offline must not claim dispatch sent; uses offline WARNING copy."""
    result = _run_export(
        tmp_path,
        label="keendns-apply-offline",
        script_body="""
const outcome = mod.describeKeendnsApplyOutcome({ overall: 'dispatched_offline' });
console.log(JSON.stringify({
  hubState: outcome.hubState,
  title: outcome.title,
  message: outcome.message,
  dispatchTitle: mod.KEENDNS_APPLY_DISPATCH_TITLE,
  dispatchHonesty: mod.KEENDNS_APPLY_DISPATCH_HONESTY,
}));
""",
    )
    assert result["hubState"] == "WARNING"
    assert result["title"] == "Команда не отправлена на роутер"
    assert result["title"] != result["dispatchTitle"]
    assert result["message"] != result["dispatchHonesty"]
    assert "Команда отправлена" not in result["message"]
    assert "не менялись" in result["message"]


@pytest.mark.parametrize(
    "overall,expected_hub_state,uses_dispatch_constants",
    [
        ("failed", "ERROR", False),
        ("applied", "WARNING", True),
    ],
)
def test_domain_describe_keendns_apply_outcome_failed_and_applied(
    tmp_path: Path,
    overall: str,
    expected_hub_state: str,
    uses_dispatch_constants: bool,
) -> None:
    """failed → ERROR; applied → existing KEENDNS_APPLY_DISPATCH_* WARNING."""
    result = _run_export(
        tmp_path,
        label=f"keendns-apply-{overall}",
        script_body=f"""
const outcome = mod.describeKeendnsApplyOutcome({{ overall: {json.dumps(overall)} }});
console.log(JSON.stringify({{
  hubState: outcome.hubState,
  title: outcome.title,
  message: outcome.message,
  dispatchTitle: mod.KEENDNS_APPLY_DISPATCH_TITLE,
  dispatchHonesty: mod.KEENDNS_APPLY_DISPATCH_HONESTY,
}}));
""",
    )
    assert result["hubState"] == expected_hub_state
    if uses_dispatch_constants:
        assert result["title"] == result["dispatchTitle"]
        assert result["message"] == result["dispatchHonesty"]
    else:
        assert result["hubState"] == "ERROR"
        assert result["title"] != result["dispatchTitle"]


def test_domain_publish_apply_confirm_title_not_cloud_overclaim() -> None:
    """Apply confirm title must not overclaim cloud registration as already done."""
    source = DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")
    confirm_body = _extract_function_body(source, "export function openDomainPublishApplyConfirm(")
    assert confirm_body is not None
    assert "Отправить команду публикации?" in confirm_body
    assert "Опубликовать имя в облаке?" not in confirm_body


def test_domain_publish_apply_confirm_offline_guard_in_source() -> None:
    """openDomainPublishApplyConfirm must fail-closed on offline param or navigator.onLine."""
    source = DOMAIN_SIMPLE_PUBLISH_JS.read_text(encoding="utf-8")
    confirm_body = _extract_function_body(source, "export function openDomainPublishApplyConfirm(")
    assert confirm_body is not None
    assert "isPublishApplyOffline" in source
    assert "showPublishApplyOfflineToast" in source
    assert "if (isPublishApplyOffline(params))" in confirm_body
    assert confirm_body.count("isPublishApplyOffline(params)") >= 2
    assert confirm_body.count("showPublishApplyOfflineToast(params)") >= 2
    assert "tone: 'warning'" in source
    assert "Нет связи с сервером управления" in source


def test_domain_screen_open_publish_apply_modal_offline_guard() -> None:
    """Domain screen must not open publish confirm modal while offline."""
    source = DOMAIN_SCREEN_JS.read_text(encoding="utf-8")
    apply_body = _extract_function_body(source, "function openPublishApplyModal(")
    assert apply_body is not None
    assert "if (offline)" in apply_body
    assert "offline," in apply_body or "offline\n" in apply_body.replace(" ", "")


def test_overview_publish_apply_offline_guard() -> None:
    """Overview domain CTA must not open publish confirm modal while offline."""
    source = OVERVIEW_JS.read_text(encoding="utf-8")
    mount_region = source[source.find("domainMount = mountDomainSimplePublishAffordance"): source.find("entryPagesSlot.appendChild")]
    assert "onPublishApply:" in mount_region
    publish_body = mount_region[mount_region.find("onPublishApply:") : mount_region.find("});", mount_region.find("onPublishApply:"))]
    assert "if (offline)" in publish_body
    assert "openDomainPublishApplyConfirm" in publish_body


def test_domain_publish_apply_confirm_skips_modal_when_offline(tmp_path: Path) -> None:
    """Offline (param or navigator.onLine) must not open apply confirm modal."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    simple_uri = json.dumps(DOMAIN_SIMPLE_PUBLISH_JS.as_uri())
    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();

function patchElement(el) {{
  if (!el.getAttributeNames) {{
    el.getAttributeNames = () => Object.keys(el.attributes || {{}});
  }}
  return el;
}}

globalThis.document = dom.document;
const origCreateElement = dom.document.createElement.bind(dom.document);
dom.document.createElement = (tag) => patchElement(origCreateElement(tag));
dom.document.createElementNS = (_ns, tag) => patchElement(origCreateElement(tag));
dom.document.createTextNode = (text) => {{
  const node = patchElement(origCreateElement('span'));
  node.textContent = String(text ?? '');
  return node;
}};
dom.document.addEventListener = () => {{}};
dom.document.removeEventListener = () => {{}};

const sampleBtn = dom.document.createElement('button');
globalThis.HTMLElement = sampleBtn.constructor;
globalThis.HTMLButtonElement = sampleBtn.constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: false }}, configurable: true }});
globalThis.window = {{ addEventListener() {{}}, removeEventListener() {{}} }};

const mod = await import({simple_uri});

let navigatorOfflineOpened = false;
let navigatorOfflineToasted = false;
mod.openDomainPublishApplyConfirm({{
  offline: false,
  openModal: () => {{ navigatorOfflineOpened = true; return {{ close: () => {{}} }}; }},
  createButton: () => sampleBtn,
  showToast: () => {{ navigatorOfflineToasted = true; }},
  name: 'promo',
  domain: 'keenetic.pro',
  onConfirmApply: async () => ({{ overall: 'applied' }}),
}});

let paramOfflineOpened = false;
let paramOfflineToasted = false;
mod.openDomainPublishApplyConfirm({{
  offline: true,
  openModal: () => {{ paramOfflineOpened = true; return {{ close: () => {{}} }}; }},
  createButton: () => sampleBtn,
  showToast: () => {{ paramOfflineToasted = true; }},
  name: 'promo',
  domain: 'keenetic.pro',
  onConfirmApply: async () => ({{ overall: 'applied' }}),
}});

globalThis.navigator.onLine = true;
let onlineOpened = false;
mod.openDomainPublishApplyConfirm({{
  openModal: () => {{ onlineOpened = true; return {{ close: () => {{}} }}; }},
  createButton: () => sampleBtn,
  showToast: () => {{}},
  name: 'promo',
  domain: 'keenetic.pro',
  onConfirmApply: async () => ({{ overall: 'applied' }}),
}});

console.log(JSON.stringify({{
  navigatorOfflineOpened,
  navigatorOfflineToasted,
  paramOfflineOpened,
  paramOfflineToasted,
  onlineOpened,
}}));
"""
    result = _run_node_harness(script, tmp_path, "publish-confirm-offline")
    assert result["navigatorOfflineOpened"] is False
    assert result["navigatorOfflineToasted"] is True
    assert result["paramOfflineOpened"] is False
    assert result["paramOfflineToasted"] is True
    assert result["onlineOpened"] is True
