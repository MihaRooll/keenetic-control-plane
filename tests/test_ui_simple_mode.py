"""DOM-harness tests for simple-mode wizard (operator-simple-mode-ui)."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

from tests.test_config_ui import WEB, _run_ui_dom_runtime


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "ui-simple-mode.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_simple_link_unknown_not_success_green() -> None:
    script = r"""
const unknown = uiExports.deriveSimpleLinkState({});
const incomplete = uiExports.deriveSimpleLinkState({ reachability_ok: true });
const surfaceUnknown = uiExports.buildSimpleLinkStepSurface(null);
const surfacePartial = uiExports.buildSimpleLinkStepSurface({ reachability_ok: true });
document.body.appendChild(surfaceUnknown.section);
document.body.appendChild(surfacePartial.section);
const badgeUnknown = dom.queryByTestId("simple-link-state", surfaceUnknown.section);
const badgePartial = dom.queryByTestId("simple-link-state", surfacePartial.section);
console.log(JSON.stringify({
  unknown_visual: unknown.visual,
  unknown_class: unknown.cssClass,
  incomplete_visual: incomplete.visual,
  badge_unknown_class: badgeUnknown ? badgeUnknown.className : "",
  badge_partial_class: badgePartial ? badgePartial.className : "",
  badge_unknown_has_is_ok: badgeUnknown ? badgeUnknown.className.includes("is-ok") : false,
  badge_partial_has_is_ok: badgePartial ? badgePartial.className.includes("is-ok") : false,
  badge_unknown_has_is_unknown:
    badgeUnknown ? badgeUnknown.className.includes("is-unknown") : false,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["unknown_visual"] == "unknown"
    assert result["unknown_class"] == "is-unknown"
    assert result["incomplete_visual"] == "unknown"
    assert result["badge_unknown_has_is_ok"] is False
    assert result["badge_partial_has_is_ok"] is False
    assert result["badge_unknown_has_is_unknown"] is True


def test_simple_link_ok_requires_all_facts() -> None:
    script = r"""
const okFacts = {
  health_status: "green",
  reachability_ok: true,
  identity_consistent: true,
  host_key_pinned: true,
  credentials_present: true,
  evidence_fresh: true,
};
const ok = uiExports.deriveSimpleLinkState(okFacts);
const fail = uiExports.deriveSimpleLinkState({ identity_mismatch: true });
const greenStatusOnly = uiExports.deriveSimpleLinkState({ health_status: "green" });
const oneFactOnly = uiExports.deriveSimpleLinkState({ reachability_ok: true });
const fiveFactsNoStatus = uiExports.deriveSimpleLinkState({
  reachability_ok: true,
  identity_consistent: true,
  host_key_pinned: true,
  credentials_present: true,
  evidence_fresh: true,
});
const contradictoryGreenFacts = {
  health_status: "green",
  reachability_ok: true,
  identity_consistent: true,
  host_key_pinned: true,
};
const contradictoryGreen = uiExports.deriveSimpleLinkState(contradictoryGreenFacts);
const greenWithAllFive = uiExports.deriveSimpleLinkState({
  health_status: "green",
  reachability_ok: true,
  identity_consistent: true,
  host_key_pinned: true,
  credentials_present: true,
  evidence_fresh: true,
});
function badgeClass(facts) {
  const surface = uiExports.buildSimpleLinkStepSurface(facts);
  document.body.appendChild(surface.section);
  const badge = dom.queryByTestId("simple-link-state", surface.section);
  return badge ? badge.className : "";
}
console.log(JSON.stringify({
  ok_visual: ok.visual,
  ok_class: ok.cssClass,
  fail_visual: fail.visual,
  fail_class: fail.cssClass,
  green_status_only_visual: greenStatusOnly.visual,
  one_fact_only_visual: oneFactOnly.visual,
  five_facts_no_status_visual: fiveFactsNoStatus.visual,
  five_facts_no_status_badge_ok: badgeClass({
    reachability_ok: true,
    identity_consistent: true,
    host_key_pinned: true,
    credentials_present: true,
    evidence_fresh: true,
  }).includes("is-ok"),
  contradictory_green_visual: contradictoryGreen.visual,
  contradictory_green_badge_ok: badgeClass(contradictoryGreenFacts).includes("is-ok"),
  green_all_five_visual: greenWithAllFive.visual,
  green_all_five_badge_ok: badgeClass({
    health_status: "green",
    reachability_ok: true,
    identity_consistent: true,
    host_key_pinned: true,
    credentials_present: true,
    evidence_fresh: true,
  }).includes("is-ok"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["ok_visual"] == "ok"
    assert result["ok_class"] == "is-ok"
    assert result["fail_visual"] == "fail"
    assert result["fail_class"] == "is-fail"
    assert result["green_status_only_visual"] == "unknown"
    assert result["one_fact_only_visual"] == "unknown"
    assert result["five_facts_no_status_visual"] == "unknown"
    assert result["five_facts_no_status_badge_ok"] is False
    assert result["contradictory_green_visual"] == "unknown"
    assert result["contradictory_green_badge_ok"] is False
    assert result["green_all_five_visual"] == "ok"
    assert result["green_all_five_badge_ok"] is True


def test_simple_link_four_of_five_facts_not_ok() -> None:
    """F-2: exactly 4 of 5 facts true + health_status green → unknown/not ok."""
    script = r"""
const base = {
  health_status: "green",
  reachability_ok: true,
  identity_consistent: true,
  host_key_pinned: true,
  credentials_present: true,
  evidence_fresh: true,
};
const factKeys = [
  "reachability_ok",
  "identity_consistent",
  "host_key_pinned",
  "credentials_present",
  "evidence_fresh",
];
function badgeClass(facts) {
  const surface = uiExports.buildSimpleLinkStepSurface(facts);
  document.body.appendChild(surface.section);
  const badge = dom.queryByTestId("simple-link-state", surface.section);
  return badge ? badge.className : "";
}
const outcomes = factKeys.map((omitKey) => {
  const facts = Object.assign({}, base);
  delete facts[omitKey];
  const state = uiExports.deriveSimpleLinkState(facts);
  return {
    omitKey,
    visual: state.visual,
    cssClass: state.cssClass,
    badge_ok: badgeClass(facts).includes("is-ok"),
    badge_unknown: badgeClass(facts).includes("is-unknown"),
  };
});
console.log(JSON.stringify({ outcomes }));
"""
    result = _run_ui_dom_runtime(script)
    assert len(result["outcomes"]) == 5
    for row in result["outcomes"]:
        assert row["visual"] == "unknown", row["omitKey"]
        assert row["cssClass"] == "is-unknown", row["omitKey"]
        assert row["badge_ok"] is False, row["omitKey"]
        assert row["badge_unknown"] is True, row["omitKey"]


def test_simple_link_identity_mismatch_shows_reason() -> None:
    script = r"""
const facts = uiExports.mapConnectionHealthToLinkFacts({
  status: "red",
  reason_code: "identity_mismatch",
  facts: {
    reachable: true,
    host_key_match: true,
    tuple_match: false,
    credentials_present: true,
    evidence_fresh: true,
  },
});
const state = uiExports.deriveSimpleLinkState(facts);
const surface = uiExports.buildSimpleLinkStepSurface(facts);
document.body.appendChild(surface.section);
const badge = dom.queryByTestId("simple-link-state", surface.section);
const reason = dom.queryByTestId("simple-link-reason", surface.section);
console.log(JSON.stringify({
  visual: state.visual,
  cssClass: state.cssClass,
  reason: state.reason,
  badge_label: badge ? badge.textContent : "",
  reason_text: reason ? reason.textContent : null,
  badge_has_is_fail: badge ? badge.className.includes("is-fail") : false,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["visual"] == "fail"
    assert result["cssClass"] == "is-fail"
    assert result["badge_label"] == "Связи нет"
    assert result["reason_text"] == "Роутер отвечает, но это не тот, что был сохранён ранее."
    assert result["badge_has_is_fail"] is True


def test_simple_connect_autodetect_unknown_identity_states() -> None:
    script = r"""
const states = [
  "known_match",
  "known_mismatch",
  "unknown",
  "lifecycle_drift",
  "record_match_unverified",
  null,
  "",
];
const outcomes = states.map((identityState) => {
  const outcome = uiExports.classifySimpleDiscoveryIdentityState(identityState);
  return { identityState, action: outcome.action };
});
console.log(JSON.stringify({ outcomes }));
"""
    result = _run_ui_dom_runtime(script)
    by_state = {row["identityState"]: row["action"] for row in result["outcomes"]}
    assert by_state["known_match"] == "success_toast"
    assert by_state["known_mismatch"] == "mismatch_msg"
    assert by_state["unknown"] == "unknown_msg"
    assert by_state["lifecycle_drift"] == "unknown_msg"
    assert by_state["record_match_unverified"] == "unknown_msg"
    assert by_state[None] == "unknown_msg"
    assert by_state[""] == "unknown_msg"


def test_simple_mode_manifest_discovery_and_health_tooltips() -> None:
    script = r"""
(async () => {
const manifestPath = process.argv[1].replace(/app\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
const connect = uiExports.buildSimpleConnectStepSurface();
const link = uiExports.buildSimpleLinkStepSurface(null);
document.body.appendChild(connect.section);
document.body.appendChild(link.section);
connect.advancedDetails.open = true;
link.advancedDetails.open = true;
const gwTip = dom.queryByTestId(
  "simple-discovery-include-gateway-tooltip",
  connect.form,
);
console.log(JSON.stringify({
  discovery_gateway_tooltip: !!gwTip,
  discovery_probe_default: document.getElementById("simple-discovery-probe").checked,
  health_probe_default: document.getElementById("simple-health-probe").checked,
  health_probe_tooltip: !!dom.queryByTestId("simple-health-probe-tooltip", link.section),
  discovery_body: connect.readDiscoveryBody(),
}));
})().catch((err) => { console.error(err); process.exit(1); });
"""
    result = _run_ui_dom_runtime(script)
    assert result["discovery_gateway_tooltip"] is True
    assert result["discovery_probe_default"] is False
    assert result["health_probe_default"] is True
    assert result["health_probe_tooltip"] is True
    assert result["discovery_body"]["include_default_gateway"] is True
    assert result["discovery_body"]["include_known_endpoints"] is True
    assert result["discovery_body"]["probe"] is False


def test_simple_domain_step_has_no_publish_action() -> None:
    script = r"""
const domain = uiExports.buildSimpleDomainStepSurface();
document.body.appendChild(domain.section);
const buttons = domain.section.querySelectorAll("button");
const links = domain.section.querySelectorAll("a");
const visible = dom.collectVisibleText(domain.section);
const publishLike = Array.from(buttons).some((btn) => {
  const t = (btn.textContent || "").toLowerCase();
  return t.includes("опублик") || t.includes("publish") || t.includes("keendns");
});
const previewBtn = dom.queryByTestId("simple-domain-preview", domain.section);
console.log(JSON.stringify({
  button_count: buttons.length,
  link_count: links.length,
  has_publish_like_button: publishLike,
  has_preview_button: !!previewBtn,
  preview_label: previewBtn ? previewBtn.textContent.trim() : "",
  mentions_cloud_permission: visible.toLowerCase().includes("облач"),
  mentions_human_gate: visible.toLowerCase().includes("human gate") || visible.includes("T4"),
  has_status_panel: !!dom.queryByTestId("simple-domain-status", domain.section),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_publish_like_button"] is False
    assert result["has_preview_button"] is True
    assert result["preview_label"] == "Предпросмотр"
    assert result["mentions_cloud_permission"] is True
    assert result["has_status_panel"] is True


def test_simple_vpn_no_traffic_routing_or_killswitch_action() -> None:
    script = r"""
const surface = uiExports.buildSimpleModeSurface({ linkFacts: null });
document.body.appendChild(surface.root);
uiExports.initSimpleWizardFromSurface(surface.root, surface, null);
uiExports.goSimpleWizardStep(4, { updateHash: false });
const vpnSection = dom.queryByTestId("simple-step-vpn", surface.root);
const visible = vpnSection
  ? dom.collectVisibleText(vpnSection)
  : dom.collectVisibleText(surface.root);
const buttons = vpnSection ? vpnSection.querySelectorAll("button") : [];
const trafficBtn = Array.from(buttons).some((btn) => {
  const t = (btn.textContent || "").toLowerCase();
  return (
    t.includes("маршрут")
    || t.includes("трафик")
    || t.includes("kill-switch")
    || t.includes("killswitch")
  ) && !btn.getAttribute("disabled");
});
console.log(JSON.stringify({
  has_traffic_honesty: visible.includes("tunnel_healthy"),
  has_kill_switch_honesty: visible.toLowerCase().includes("kill-switch"),
  enabled_traffic_like_button: trafficBtn,
  import_submit_present: !!dom.queryByTestId("vpn-import-submit", surface.root),
  import_details_closed: (() => {
    const details = dom.queryByTestId("simple-vpn-import-details", surface.root);
    return details ? details.open === false : null;
  })(),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_traffic_honesty"] is True
    assert result["has_kill_switch_honesty"] is True
    assert result["enabled_traffic_like_button"] is False
    assert result["import_submit_present"] is True
    assert result["import_details_closed"] is True


def test_simple_wizard_shows_one_step_at_a_time() -> None:
    script = r"""
const surface = uiExports.buildSimpleModeSurface({ linkFacts: null });
document.body.appendChild(surface.root);
uiExports.initSimpleWizardFromSurface(surface.root, surface, null);
function visibleStepCount() {
  return surface.stepNodes.filter((node) => !node.hidden).length;
}
const initial = visibleStepCount();
uiExports.goSimpleWizardStep(3, { updateHash: false });
const onStep3 = visibleStepCount();
const uplinkVisible = !dom.queryByTestId("simple-step-wifi-uplink", surface.root).hidden;
const connectHidden = dom.queryByTestId("simple-step-connect", surface.root).hidden;
console.log(JSON.stringify({
  initial_visible_count: initial,
  step3_visible_count: onStep3,
  uplink_visible: uplinkVisible,
  connect_hidden: connectHidden,
  has_stepper: !!dom.queryByTestId("simple-wizard-step-1", surface.root),
  has_back: !!dom.queryByTestId("simple-wizard-back", surface.root),
  has_next: !!dom.queryByTestId("simple-wizard-next", surface.root),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["initial_visible_count"] == 1
    assert result["step3_visible_count"] == 1
    assert result["uplink_visible"] is True
    assert result["connect_hidden"] is True
    assert result["has_stepper"] is True
    assert result["has_back"] is True
    assert result["has_next"] is True


def test_simple_wizard_stepper_navigates_steps() -> None:
    script = r"""
const surface = uiExports.buildSimpleModeSurface({ linkFacts: null });
document.body.appendChild(surface.root);
uiExports.initSimpleWizardFromSurface(surface.root, surface, null);
dom.queryByTestId("simple-wizard-step-5", surface.root).click();
const guestVisible = !dom.queryByTestId("simple-step-guest-wifi", surface.root).hidden;
dom.queryByTestId("simple-wizard-step-2", surface.root).click();
const linkVisible = !dom.queryByTestId("simple-step-link", surface.root).hidden;
console.log(JSON.stringify({
  guest_visible_after_step5_click: guestVisible,
  link_visible_after_step2_click: linkVisible,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["guest_visible_after_step5_click"] is True
    assert result["link_visible_after_step2_click"] is True


def test_simple_wizard_next_back_bounds() -> None:
    script = r"""
const surface = uiExports.buildSimpleModeSurface({ linkFacts: null, initialStep: 1 });
document.body.appendChild(surface.root);
uiExports.initSimpleWizardFromSurface(surface.root, surface, null);
const back = dom.queryByTestId("simple-wizard-back", surface.root);
const next = dom.queryByTestId("simple-wizard-next", surface.root);
function currentStep() {
  return surface.stepNodes.findIndex((node) => !node.hidden) + 1;
}
const step1BackHidden = back.hidden;
const startStep = currentStep();
next.click();
const afterNext = currentStep();
back.click();
const afterBack = currentStep();
uiExports.goSimpleWizardStep(uiExports.SIMPLE_WIZARD_STEP_COUNT, { updateHash: false });
const onLast = currentStep();
const lastStepNextLabel = next.textContent.trim();
next.click();
const afterNextOnLast = currentStep();
console.log(JSON.stringify({
  step1_back_hidden: step1BackHidden,
  start_step: startStep,
  after_next: afterNext,
  after_back: afterBack,
  on_last: onLast,
  last_step_next_label: lastStepNextLabel,
  after_next_on_last: afterNextOnLast,
  last_step_number: uiExports.SIMPLE_WIZARD_STEP_COUNT,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["step1_back_hidden"] is True
    assert result["start_step"] == 1
    assert result["after_next"] == 2
    assert result["after_back"] == 1
    assert result["on_last"] == 7
    assert result["last_step_next_label"] == "Готово"
    assert result["after_next_on_last"] == 7
    assert result["last_step_number"] == 7


def test_simple_wizard_hash_deeplink_parse_and_initial_step() -> None:
    script = r"""
const parsedStep4 = uiExports.parseSimpleWizardStep(["step-4"]);
const parsedBare3 = uiExports.parseSimpleWizardStep(["3"]);
const parsedClamp = uiExports.parseSimpleWizardStep(["step-99"]);
const surface = uiExports.buildSimpleModeSurface({ linkFacts: null, initialStep: parsedStep4 });
document.body.appendChild(surface.root);
uiExports.initSimpleWizardFromSurface(surface.root, surface, null);
const vpnVisible = !dom.queryByTestId("simple-step-vpn", surface.root).hidden;
const connectHidden = dom.queryByTestId("simple-step-connect", surface.root).hidden;
console.log(JSON.stringify({
  parsed_step4: parsedStep4,
  parsed_bare3: parsedBare3,
  parsed_clamp: parsedClamp,
  vpn_visible: vpnVisible,
  connect_hidden: connectHidden,
  current_step: surface.stepNodes.findIndex((node) => !node.hidden) + 1,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["parsed_step4"] == 4
    assert result["parsed_bare3"] == 3
    assert result["parsed_clamp"] == 7
    assert result["vpn_visible"] is True
    assert result["connect_hidden"] is True
    assert result["current_step"] == 4


def test_simple_wizard_step2_done_live_not_sticky() -> None:
    """F-1: step 2 done follows live link visual; stale session flag must not stick."""
    script = r"""
const okFacts = {
  health_status: "green",
  reachability_ok: true,
  identity_consistent: true,
  host_key_pinned: true,
  credentials_present: true,
  evidence_fresh: true,
};
const failFacts = { health_unavailable: true, explicit_unreachable: true, health_status: "red" };
uiExports.markSimpleWizardStepDone(2);
const okDone = uiExports.isSimpleWizardStepDone(2, okFacts);
const failNotDone = uiExports.isSimpleWizardStepDone(2, failFacts);
const surfaceOk = uiExports.buildSimpleModeSurface({ linkFacts: okFacts });
document.body.appendChild(surfaceOk.root);
uiExports.initSimpleWizardFromSurface(surfaceOk.root, surfaceOk, okFacts);
const step2BtnOk = dom.queryByTestId("simple-wizard-step-2", surfaceOk.root);
const step2LiOk = step2BtnOk ? step2BtnOk.parentNode : null;
const step2DoneClassOk = step2LiOk ? step2LiOk.classList.contains("is-done") : false;
document.body.innerHTML = "";
const surfaceFail = uiExports.buildSimpleModeSurface({ linkFacts: failFacts });
document.body.appendChild(surfaceFail.root);
uiExports.initSimpleWizardFromSurface(surfaceFail.root, surfaceFail, failFacts);
const step2BtnFail = dom.queryByTestId("simple-wizard-step-2", surfaceFail.root);
const step2LiFail = step2BtnFail ? step2BtnFail.parentNode : null;
const step2DoneClassFail = step2LiFail ? step2LiFail.classList.contains("is-done") : false;
console.log(JSON.stringify({
  ok_done: okDone,
  fail_not_done: failNotDone,
  step2_done_class_ok: step2DoneClassOk,
  step2_done_class_fail: step2DoneClassFail,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["ok_done"] is True
    assert result["fail_not_done"] is False
    assert result["step2_done_class_ok"] is True
    assert result["step2_done_class_fail"] is False


def test_simple_wizard_domain_preview_step6_honesty() -> None:
    """F-2: step 6 done only on documentation_sourced_unconfirmed preview status."""
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
const manifestPath = process.argv[1].replace(/app\\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
async function previewAndCheck(verificationStatus) {{
  uiExports.setApiFetchStubForTest(async (path) => {{
    if (path === "/routers") {{
      return {{ data: {{ items: [] }}, status: 200 }};
    }}
    if (path === "/keendns/status") {{
      return {{ data: {{ feature_availability: "unknown" }}, status: 200 }};
    }}
    if (path === "/keendns/preview") {{
      const data = verificationStatus === "__empty__"
        ? {{}}
        : {{ verification_status: verificationStatus }};
      return {{ data, status: 200 }};
    }}
    return {{ data: {{}}, status: 200 }};
  }});
  const root = document.createElement("div");
  document.body.appendChild(root);
  await uiExports.renderSimpleMode(root);
  uiExports.goSimpleWizardStep(6, {{ updateHash: false }});
  document.getElementById("simple-domain-name").value = "my-router";
  document.getElementById("simple-domain-domain").value = "keenetic.link";
  dom.queryByTestId("simple-domain-preview", root).click();
  await flushUiAsync();
  return uiExports.isSimpleWizardStepDone(6, null);
}}
const rejectedDone = await previewAndCheck("rejected");
document.body.innerHTML = "";
const emptyDone = await previewAndCheck("__empty__");
document.body.innerHTML = "";
const confirmedDone = await previewAndCheck("documentation_sourced_unconfirmed");
console.log(JSON.stringify({{
  rejected_marks_done: rejectedDone,
  empty_marks_done: emptyDone,
  confirmed_marks_done: confirmedDone,
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["rejected_marks_done"] is False
    assert result["empty_marks_done"] is False
    assert result["confirmed_marks_done"] is True


def test_simple_wizard_vpn_import_step4_honesty() -> None:
    """F-6: step 4 done only after catalog import returns profile_id."""
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
const manifestPath = process.argv[1].replace(/app\\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
async function importAndCheck(importData) {{
  uiExports.setApiFetchStubForTest(async (path) => {{
    if (path === "/routers") {{
      return {{ data: {{ items: [] }}, status: 200 }};
    }}
    if (path === "/vpn-profiles/import") {{
      return {{ data: importData, status: 200 }};
    }}
    return {{ data: {{}}, status: 200 }};
  }});
  const root = document.createElement("div");
  document.body.appendChild(root);
  await uiExports.renderSimpleMode(root);
  uiExports.goSimpleWizardStep(4, {{ updateHash: false }});
  document.getElementById("vpn-import-display-name").value = "Lab VPN";
  dom.queryByTestId("vpn-import-submit", root).click();
  await flushUiAsync();
  return uiExports.isSimpleWizardStepDone(4, null);
}}
const emptyDone = await importAndCheck({{}});
document.body.innerHTML = "";
const withProfileDone = await importAndCheck({{
  profile_id: "prof_test",
  display_name: "Lab VPN",
  vpn_kind: "AmneziaWG",
}});
console.log(JSON.stringify({{
  with_profile_marks_done: withProfileDone,
  empty_marks_done: emptyDone,
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["with_profile_marks_done"] is True
    assert result["empty_marks_done"] is False


def test_ui_mode_default_simple_and_persists() -> None:
    script = r"""
localStorage.clear();
document.documentElement.setAttribute("data-ui-mode", "simple");
const html = document.createElement("html");
html.setAttribute("id", "ui-mode-html");
document.body.appendChild(html);
const simpleBtn = document.createElement("button");
simpleBtn.classList.add("btn", "btn-ui-mode");
simpleBtn.setAttribute("data-ui-mode-value", "simple");
simpleBtn.setAttribute("id", "ui-mode-simple");
document.body.appendChild(simpleBtn);
const expertBtn = document.createElement("button");
expertBtn.classList.add("btn", "btn-ui-mode");
expertBtn.setAttribute("data-ui-mode-value", "expert");
expertBtn.setAttribute("id", "ui-mode-expert");
document.body.appendChild(expertBtn);
uiExports.initUiMode();
const defaultMode = uiExports.getCurrentUiMode();
uiExports.applyUiMode("expert", { navigate: false });
const afterExpert = localStorage.getItem(uiExports.UI_MODE_KEY);
const expertPressed = expertBtn.getAttribute("aria-pressed");
uiExports.applyUiMode("simple", { navigate: false });
const afterSimple = localStorage.getItem(uiExports.UI_MODE_KEY);
console.log(JSON.stringify({
  default_mode: defaultMode,
  after_expert: afterExpert,
  after_simple: afterSimple,
  expert_pressed: expertPressed,
  html_mode: document.documentElement.getAttribute("data-ui-mode"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["default_mode"] == "simple"
    assert result["after_expert"] == "expert"
    assert result["after_simple"] == "simple"
    assert result["expert_pressed"] == "true"
    assert result["html_mode"] == "simple"


def test_simple_connect_password_omitname_and_mode_storage_safe() -> None:
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface();
document.body.appendChild(connect.section);
const secret = document.getElementById("wizard-secret");
localStorage.setItem(uiExports.UI_MODE_KEY, "simple");
const stored = localStorage.getItem(uiExports.UI_MODE_KEY);
console.log(JSON.stringify({
  secret_has_name: secret ? secret.getAttribute("name") : "missing",
  secret_type: secret ? secret.getAttribute("type") : null,
  stored_mode: stored,
  stored_is_simple_token: stored === "simple",
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["secret_has_name"] in (None, "missing", "")
    assert result["secret_type"] == "password"
    assert result["stored_is_simple_token"] is True
    assert result["stored_mode"] == "simple"


def test_simple_guest_wifi_honesty_and_no_isolation_apply() -> None:
    script = r"""
const guest = uiExports.buildSimpleGuestWifiStepSurface();
document.body.appendChild(guest.section);
const payload = guest.readPayload(false);
const visible = dom.collectVisibleText(guest.section);
console.log(JSON.stringify({
  guest_isolation_false: payload.guest_isolation === false,
  has_isolation_honesty: visible.includes("422 wifi.guest_isolation_unsupported"),
  has_test_ap_caption: visible.toLowerCase().includes("test ap"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["guest_isolation_false"] is True
    assert result["has_isolation_honesty"] is True
    assert result["has_test_ap_caption"] is True


def test_simple_mode_html_contract(authed_client) -> None:
    html = authed_client.get("/settings/router-control").text
    assert 'data-ui-mode="simple"' in html
    assert 'id="ui-mode-simple"' in html
    assert 'id="ui-mode-expert"' in html
    assert 'data-view="simple"' in html
    assert "Мастер настройки" in html


def test_app_js_simple_mode_exports() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'const UI_MODE_KEY = "rc.prototype.uiMode"' in source
    assert "function deriveSimpleLinkState" in source
    assert "function mapConnectionHealthToLinkFacts" in source
    assert "function fetchSimpleLinkFacts" in source
    assert 'case "simple":' in source
    assert "function buildSimpleModeSurface" in source


def test_simple_link_gate_a_open_alone_not_green() -> None:
    script = r"""
const gateAOnly = uiExports.buildSimpleLinkFactsFromApis({
  gate_a: { status: "open", ssh_host_key_algorithm: "ssh-ed25519" },
}, null, null);
const state = uiExports.deriveSimpleLinkState(gateAOnly);
const surface = uiExports.buildSimpleLinkStepSurface(gateAOnly);
document.body.appendChild(surface.section);
const badge = dom.queryByTestId("simple-link-state", surface.section);
console.log(JSON.stringify({
  visual: state.visual,
  cssClass: state.cssClass,
  badge_has_is_ok: badge ? badge.className.includes("is-ok") : false,
  badge_has_is_unknown: badge ? badge.className.includes("is-unknown") : false,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["visual"] == "unknown"
    assert result["cssClass"] == "is-unknown"
    assert result["badge_has_is_ok"] is False
    assert result["badge_has_is_unknown"] is True


def test_simple_link_connection_health_mapping() -> None:
    script = r"""
function badgeClass(facts) {
  const surface = uiExports.buildSimpleLinkStepSurface(facts);
  document.body.appendChild(surface.section);
  const badge = dom.queryByTestId("simple-link-state", surface.section);
  return badge ? badge.className : "";
}
const green = uiExports.mapConnectionHealthToLinkFacts({
  status: "green",
  facts: {
    reachable: true,
    host_key_match: true,
    tuple_match: true,
    credentials_present: true,
    evidence_fresh: true,
  },
});
const yellow = uiExports.mapConnectionHealthToLinkFacts({
  status: "yellow",
  facts: {
    reachable: true,
    host_key_match: true,
    tuple_match: null,
    credentials_present: true,
    evidence_fresh: true,
  },
});
const red = uiExports.mapConnectionHealthToLinkFacts({
  status: "red",
  facts: {
    reachable: false,
    host_key_match: null,
    tuple_match: null,
    credentials_present: null,
    evidence_fresh: null,
  },
});
console.log(JSON.stringify({
  green_visual: uiExports.deriveSimpleLinkState(green).visual,
  green_class: uiExports.deriveSimpleLinkState(green).cssClass,
  yellow_visual: uiExports.deriveSimpleLinkState(yellow).visual,
  red_visual: uiExports.deriveSimpleLinkState(red).visual,
  red_class: uiExports.deriveSimpleLinkState(red).cssClass,
  green_badge_ok: badgeClass(green).includes("is-ok"),
  yellow_badge_unknown: badgeClass(yellow).includes("is-unknown"),
  red_badge_fail: badgeClass(red).includes("is-fail"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["green_visual"] == "ok"
    assert result["green_class"] == "is-ok"
    assert result["green_badge_ok"] is True
    assert result["yellow_visual"] == "unknown"
    assert result["yellow_badge_unknown"] is True
    assert result["red_visual"] == "fail"
    assert result["red_class"] == "is-fail"
    assert result["red_badge_fail"] is True


def test_simple_link_yellow_evidence_stale_not_ok() -> None:
    """F-7: three positive link facts + yellow/evidence_stale must not render is-ok."""
    script = r"""
function badgeClass(facts) {
  const surface = uiExports.buildSimpleLinkStepSurface(facts);
  document.body.appendChild(surface.section);
  const badge = dom.queryByTestId("simple-link-state", surface.section);
  return badge ? badge.className : "";
}
const stale = uiExports.mapConnectionHealthToLinkFacts({
  status: "yellow",
  reason_code: "evidence_stale",
  facts: {
    reachable: true,
    host_key_match: true,
    tuple_match: true,
    credentials_present: true,
    evidence_fresh: false,
  },
});
const state = uiExports.deriveSimpleLinkState(stale);
console.log(JSON.stringify({
  visual: state.visual,
  cssClass: state.cssClass,
  badge_has_is_ok: badgeClass(stale).includes("is-ok"),
  badge_has_is_unknown: badgeClass(stale).includes("is-unknown"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["visual"] == "unknown"
    assert result["cssClass"] == "is-unknown"
    assert result["badge_has_is_ok"] is False
    assert result["badge_has_is_unknown"] is True


def test_simple_link_red_credentials_missing_is_fail() -> None:
    """F-7: red health with credentials_present false must render is-fail."""
    script = r"""
function badgeClass(facts) {
  const surface = uiExports.buildSimpleLinkStepSurface(facts);
  document.body.appendChild(surface.section);
  const badge = dom.queryByTestId("simple-link-state", surface.section);
  return badge ? badge.className : "";
}
const missingCreds = uiExports.mapConnectionHealthToLinkFacts({
  status: "red",
  reason_code: "credentials_missing",
  facts: {
    reachable: true,
    host_key_match: true,
    tuple_match: true,
    credentials_present: false,
    evidence_fresh: true,
  },
});
const state = uiExports.deriveSimpleLinkState(missingCreds);
console.log(JSON.stringify({
  visual: state.visual,
  cssClass: state.cssClass,
  credentials_missing: missingCreds.credentials_missing === true,
  badge_has_is_fail: badgeClass(missingCreds).includes("is-fail"),
  badge_has_is_ok: badgeClass(missingCreds).includes("is-ok"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["visual"] == "fail"
    assert result["cssClass"] == "is-fail"
    assert result["credentials_missing"] is True
    assert result["badge_has_is_fail"] is True
    assert result["badge_has_is_ok"] is False


def test_simple_link_transport_error_unknown_not_fail() -> None:
    script = r"""
const facts = uiExports.buildSimpleLinkFactsFromApis(null, null, "network error");
const state = uiExports.deriveSimpleLinkState(facts);
console.log(JSON.stringify({
  visual: state.visual,
  cssClass: state.cssClass,
  has_explicit_unreachable: facts.explicit_unreachable === true,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["visual"] == "unknown"
    assert result["cssClass"] == "is-unknown"
    assert result["has_explicit_unreachable"] is False


def test_simple_connect_autodetect_enabled() -> None:
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface();
document.body.appendChild(connect.section);
const btn = dom.queryByTestId("simple-connect-autodetect", connect.section);
const visible = dom.collectVisibleText(connect.section);
console.log(JSON.stringify({
  btn_disabled: btn ? btn.disabled === true : true,
  mentions_route_absent: visible.toLowerCase().includes("route отсутствует")
    || visible.toLowerCase().includes("composite route"),
  mentions_password: visible.toLowerCase().includes("пароль"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["btn_disabled"] is False
    assert result["mentions_route_absent"] is False
    assert result["mentions_password"] is True


def test_simple_guest_wifi_sanitized_result() -> None:
    script = r"""
const guest = uiExports.buildSimpleGuestWifiStepSurface();
document.body.appendChild(guest.section);
const payload = {
  overall: "applied",
  management_password: "should-redact",
  on_air_verification_status: "on_air_verified",
};
guest.renderResult(payload);
const visible = guest.resultBox.textContent || "";
console.log(JSON.stringify({
  has_secret: visible.includes("should-redact"),
  has_overall: visible.includes("applied"),
  has_redacted: visible.includes("[REDACTED]"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_secret"] is False
    assert result["has_overall"] is True
    assert result["has_redacted"] is True


def test_simple_families_expert_link_switches_mode() -> None:
    script = r"""
document.documentElement.setAttribute("data-ui-mode", "simple");
const families = uiExports.buildSimpleFamiliesStepSurface();
document.body.appendChild(families.details);
const link = dom.queryByTestId("simple-families-expert-link", families.details);
const hasExpertClass = link ? link.className.includes("nav-link-expert-entry") : false;
if (link) link.click();
console.log(JSON.stringify({
  has_expert_class: hasExpertClass,
  mode_after_click: document.documentElement.getAttribute("data-ui-mode"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_expert_class"] is True
    assert result["mode_after_click"] == "expert"


_GREEN_ALL_FIVE = {
    "has_enrolled_router": True,
    "router_id": "lab-router-1",
    "host": "192.168.2.1",
    "display_name": "Lab router",
    "health_status": "green",
    "reachability_ok": True,
    "identity_consistent": True,
    "host_key_pinned": True,
    "credentials_present": True,
    "evidence_fresh": True,
    "loaded": True,
}


def test_simple_connect_enrolled_green_collapsed_summary() -> None:
    """(a) enrolled + honest green → collapsed summary + form in details."""
    import json

    script = (
        r"""
function isDescendantOf(node, ancestor) {
  let cur = node;
  while (cur) {
    if (cur === ancestor) return true;
    cur = cur.parentNode;
  }
  return false;
}
const linkFacts = """
        + json.dumps(_GREEN_ALL_FIVE)
        + r""";
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts });
document.body.appendChild(connect.section);
const summary = dom.queryByTestId("simple-connect-summary", connect.section);
const edit = dom.queryByTestId("simple-connect-edit", connect.section);
const fail = dom.queryByTestId("simple-connect-auto-fail", connect.section);
const hostInput = dom.queryByTestId("wizard-host", connect.section);
const form = connect.form;
const details = dom.queryByTestId("simple-connect-form-details", connect.section);
const collapsedVisible = dom.collectVisibleText(connect.section);
const detailsOpenInitially = details ? details.open === true : null;
if (edit && details) {
  details.open = true;
}
const expandedVisible = dom.collectVisibleText(connect.section);
console.log(JSON.stringify({
  summary_text: summary ? summary.textContent.trim() : "",
  summary_in_visible: collapsedVisible.includes("Подключено"),
  edit_present: !!edit,
  fail_present: !!fail,
  form_present: !!form,
  host_input_present: !!hostInput,
  details_present: !!details,
  form_inside_details: !!(form && details && isDescendantOf(form, details)),
  form_not_section_sibling: !!(form && connect.section.children.indexOf(form) < 0),
  details_open_initially: detailsOpenInitially,
  details_open_after_edit: details ? details.open === true : null,
  collapsed_has_form_label: collapsedVisible.includes("Адрес роутера"),
  expanded_has_form_label: expandedVisible.includes("Адрес роутера"),
  mentions_connected: summary ? summary.textContent.includes("Подключено") : false,
  mentions_lab: summary ? summary.textContent.includes("Lab router") : false,
}));
"""
    )
    result = _run_ui_dom_runtime(script)
    assert result["summary_in_visible"] is True
    assert result["mentions_connected"] is True
    assert result["mentions_lab"] is True
    assert result["edit_present"] is True
    assert result["fail_present"] is False
    assert result["form_present"] is True
    assert result["host_input_present"] is True
    assert result["details_present"] is True
    assert result["form_inside_details"] is True
    assert result["form_not_section_sibling"] is True
    assert result["details_open_initially"] is False
    assert result["details_open_after_edit"] is True
    assert result["collapsed_has_form_label"] is False
    assert result["expanded_has_form_label"] is True


def test_simple_connect_enrolled_non_green_form_open_with_fail_message() -> None:
    """(b) enrolled + non-green → auto-fail message + expanded form."""
    import json

    fail_facts = {
        "has_enrolled_router": True,
        "router_id": "lab-router-1",
        "host": "192.168.2.1",
        "health_status": "red",
        "explicit_unreachable": True,
        "loaded": True,
    }
    script = (
        r"""
const linkFacts = """
        + json.dumps(fail_facts)
        + r""";
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts });
document.body.appendChild(connect.section);
const summary = dom.queryByTestId("simple-connect-summary", connect.section);
const fail = dom.queryByTestId("simple-connect-auto-fail", connect.section);
const form = dom.queryByTestId("wizard-host", connect.section);
const details = dom.queryByTestId("simple-connect-form-details", connect.section);
const visible = dom.collectVisibleText(connect.section);
console.log(JSON.stringify({
  summary_present: !!summary,
  fail_present: !!fail,
  fail_in_visible: dom.collectVisibleText(connect.section).includes("автоматически"),
  fail_mentions_auto: fail ? fail.textContent.includes("автоматически") : false,
  form_present: !!form,
  form_in_visible: dom.collectVisibleText(connect.section).includes("Адрес роутера"),
  details_present: !!details,
  visible_has_connected: visible.includes("Подключено"),
}));
"""
    )
    result = _run_ui_dom_runtime(script)
    assert result["summary_present"] is False
    assert result["fail_present"] is True
    assert result["fail_in_visible"] is True
    assert result["fail_mentions_auto"] is True
    assert result["form_present"] is True
    assert result["form_in_visible"] is True
    assert result["details_present"] is False
    assert result["visible_has_connected"] is False


def test_simple_connect_no_enrolled_form_expanded_regression() -> None:
    """(c) no enrolled router → form expanded, no connected summary or auto-fail."""
    import json

    script = (
        r"""
const linkFacts = """
        + json.dumps({"no_target": True, "has_enrolled_router": False, "loaded": False})
        + r""";
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts });
document.body.appendChild(connect.section);
const summary = dom.queryByTestId("simple-connect-summary", connect.section);
const fail = dom.queryByTestId("simple-connect-auto-fail", connect.section);
const form = dom.queryByTestId("wizard-host", connect.section);
const details = dom.queryByTestId("simple-connect-form-details", connect.section);
const btn = dom.queryByTestId("simple-connect-autodetect", connect.section);
console.log(JSON.stringify({
  summary_present: !!summary,
  fail_present: !!fail,
  form_present: !!form,
  form_in_visible: dom.collectVisibleText(connect.section).includes("Адрес роутера"),
  details_present: !!details,
  btn_disabled: btn ? btn.disabled === true : true,
}));
"""
    )
    result = _run_ui_dom_runtime(script)
    assert result["summary_present"] is False
    assert result["fail_present"] is False
    assert result["form_present"] is True
    assert result["form_in_visible"] is True
    assert result["details_present"] is False
    assert result["btn_disabled"] is False


def test_simple_connect_adversarial_incomplete_facts_not_connected() -> None:
    """(d) incomplete/corrupt health facts must not render Step 1 connected success."""
    import json

    cases = [
        {
            "has_enrolled_router": True,
            "router_id": "lab-router-1",
            "health_status": "green",
            "reachability_ok": True,
            "identity_consistent": True,
            "host_key_pinned": True,
            "credentials_present": True,
            "loaded": True,
        },
        {
            "has_enrolled_router": True,
            "router_id": "lab-router-1",
            "health_status": "green",
            "reachability_ok": True,
            "identity_consistent": True,
            "host_key_pinned": True,
            "credentials_present": True,
            "evidence_fresh": False,
            "loaded": True,
        },
        {
            "has_enrolled_router": True,
            "router_id": "lab-router-1",
            "health_status": "green",
            "reachability_ok": True,
            "host_key_pinned": True,
            "credentials_present": True,
            "evidence_fresh": True,
            "loaded": True,
        },
        {
            "has_enrolled_router": True,
            "router_id": "lab-router-1",
            "host": "192.168.2.1",
            "health_status": "yellow",
            "reachability_ok": True,
            "identity_consistent": True,
            "host_key_pinned": True,
            "credentials_present": True,
            "evidence_fresh": True,
            "loaded": True,
        },
        {
            "has_enrolled_router": True,
            "router_id": "lab-router-1",
            "host": "192.168.2.1",
            "health_unavailable": True,
            "loaded": True,
        },
    ]
    script = (
        r"""
const cases = """
        + json.dumps(cases)
        + r""";
const out = cases.map((linkFacts) => {
  const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts });
  document.body.appendChild(connect.section);
  const summary = dom.queryByTestId("simple-connect-summary", connect.section);
  const fail = dom.queryByTestId("simple-connect-auto-fail", connect.section);
  const visible = dom.collectVisibleText(connect.section);
  return {
    summary_present: !!summary,
    fail_present: !!fail,
    fail_in_visible: visible.includes("автоматически"),
    visible_has_connected: visible.includes("Подключено"),
    ux_mode: connect.stepUx ? connect.stepUx.mode : null,
  };
});
console.log(JSON.stringify({ cases: out }));
"""
    )
    result = _run_ui_dom_runtime(script)
    for case in result["cases"]:
        assert case["summary_present"] is False
        assert case["visible_has_connected"] is False
        assert case["ux_mode"] != "connected"
        assert case["ux_mode"] == "auto_fail"
        assert case["fail_present"] is True
        assert case["fail_in_visible"] is True


_FLUSH_ASYNC = """
async function flushUiAsync() {
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
}
"""


def test_simple_wifi_uplink_step_renders_manifest_fields() -> None:
    script = r"""
const manifestPath = process.argv[1].replace(/app\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
const surface = uiExports.buildSimpleModeSurface({ linkFacts: null });
document.body.appendChild(surface.root);
uiExports.initSimpleWizardFromSurface(surface.root, surface, null);
uiExports.goSimpleWizardStep(3, { updateHash: false });
const uplinkSection = dom.queryByTestId("simple-step-wifi-uplink", surface.root);
const ssid = dom.queryByTestId("simple-uplink-ssid", uplinkSection);
const band = dom.queryByTestId("simple-uplink-band", uplinkSection);
const cred = dom.queryByTestId("simple-uplink-credential-ref", uplinkSection);
const confirm = dom.queryByTestId("simple-uplink-confirm", uplinkSection);
const title = uplinkSection ? uplinkSection.querySelector("h2") : null;
const credField = dom.queryByTestId("simple-uplink-credential-ref-field", uplinkSection);
const credLabel = credField ? credField.querySelector("label") : null;
function findStepsContainer(root) {
  function walk(node) {
    if (!node) return null;
    if (node.className && String(node.className).includes("simple-mode-steps")) return node;
    for (const child of node.children || []) {
      const found = walk(child);
      if (found) return found;
    }
    return null;
  }
  return walk(root);
}
const stepsContainer = findStepsContainer(surface.root);
const stepOrder = stepsContainer
  ? stepsContainer.children.map((node) => node.getAttribute("data-testid"))
  : [];
const bandTooltip = dom.queryByTestId("simple-uplink-band-tooltip", uplinkSection);
console.log(JSON.stringify({
  section_present: !!uplinkSection,
  ssid_present: !!ssid,
  band_present: !!band,
  cred_present: !!cred,
  confirm_present: !!confirm,
  preview_present: !!dom.queryByTestId("simple-uplink-preview", uplinkSection),
  apply_present: !!dom.queryByTestId("simple-uplink-apply", uplinkSection),
  title_present: !!title,
  title_has_step_3: title ? title.textContent.indexOf("3") >= 0 : false,
  title_length: title ? title.textContent.length : 0,
  band_default: band ? band.value : "",
  cred_label: credLabel ? credLabel.textContent.trim() : "",
  cred_placeholder: cred ? cred.placeholder : "",
  band_tooltip_present: !!bandTooltip,
  step_order: stepOrder,
  uplink_step_visible: uplinkSection ? !uplinkSection.hidden : false,
  only_one_visible: surface.stepNodes.filter((n) => !n.hidden).length === 1,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["section_present"] is True
    assert result["uplink_step_visible"] is True
    assert result["only_one_visible"] is True
    assert result["ssid_present"] is True
    assert result["band_present"] is True
    assert result["cred_present"] is True
    assert result["confirm_present"] is True
    assert result["preview_present"] is True
    assert result["apply_present"] is True
    assert result["title_present"] is True
    assert result["title_has_step_3"] is True
    assert result["title_length"] > 10
    assert result["band_default"] == "BAND_2_4GHZ"
    assert "credential_ref" in result["cred_label"]
    assert str(result["cred_placeholder"]).startswith("credref:")
    assert result["band_tooltip_present"] is True
    assert result["step_order"] == [
        "simple-step-connect",
        "simple-step-link",
        "simple-step-wifi-uplink",
        "simple-step-vpn",
        "simple-step-guest-wifi",
        "simple-domain-step",
        "simple-step-families",
    ]


def test_simple_wifi_uplink_preview_calls_station_endpoint() -> None:
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
const manifestPath = process.argv[1].replace(/app\\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
const calls = [];
uiExports.setApiFetchStubForTest(async (path, options) => {{
  calls.push({{ path, body: options.body }});
  if (path === "/routers") {{
    return {{ data: {{ items: [] }}, status: 200 }};
  }}
  if (path === "/wifi/station/preview") {{
    return {{
      data: {{
        station_id: "WifiMaster0/Station0",
        grammar_verification_status: "grammar_ok",
        verification_status: "grammar_ok",
        planned_uplink_verification_level: "compile_only",
        apply_ops: [{{ operation: "wifi_station_set_ssid" }}],
      }},
      status: 200,
    }};
  }}
  return {{ data: {{}}, status: 200 }};
}});
const root = document.createElement("div");
document.body.appendChild(root);
await uiExports.renderSimpleMode(root);
uiExports.goSimpleWizardStep(3, {{ updateHash: false }});
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue";
document.getElementById("simple-uplink-band").value = "BAND_5GHZ";
dom.queryByTestId("simple-uplink-preview", root).click();
await flushUiAsync();
const previewBox = dom.queryByTestId("simple-uplink-preview-result", root);
const previewText = previewBox ? previewBox.textContent || "" : "";
const previewCalls = calls.filter((c) => c.path === "/wifi/station/preview");
console.log(JSON.stringify({{
  preview_call_count: previewCalls.length,
  preview_path: previewCalls.length ? previewCalls[0].path : "",
  preview_ssid: previewCalls.length ? previewCalls[0].body.ssid : "",
  preview_band: previewCalls.length ? previewCalls[0].body.band : "",
  preview_mode: previewCalls.length ? previewCalls[0].body.mode : "",
  has_grammar_status: previewText.includes("grammar_verification_status"),
  has_planned_level: previewText.includes("planned_uplink_verification_level"),
  has_ops: previewText.includes("Set station SSID"),
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["preview_call_count"] == 1
    assert result["preview_path"] == "/wifi/station/preview"
    assert result["preview_ssid"] == "Venue-WiFi"
    assert result["preview_band"] == "BAND_5GHZ"
    assert result["preview_mode"] == "WifiWan"
    assert result["has_grammar_status"] is True
    assert result["has_planned_level"] is True
    assert result["has_ops"] is True


def test_simple_wifi_uplink_apply_blocked_without_confirm() -> None:
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
const manifestPath = process.argv[1].replace(/app\\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
const calls = [];
uiExports.setApiFetchStubForTest(async (path, options) => {{
  calls.push({{ path, body: options.body }});
  if (path === "/routers") {{
    return {{ data: {{ items: [] }}, status: 200 }};
  }}
  if (path === "/wifi/station/apply") {{
    return {{ data: {{ overall: "applied" }}, status: 200 }};
  }}
  return {{ data: {{}}, status: 200 }};
}});
uiExports.resetToastCaptureForTest();
const root = document.createElement("div");
document.body.appendChild(root);
await uiExports.renderSimpleMode(root);
uiExports.goSimpleWizardStep(3, {{ updateHash: false }});
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue";
document.getElementById("simple-uplink-confirm").checked = false;
dom.queryByTestId("simple-uplink-apply", root).click();
await flushUiAsync();
const applyCalls = calls.filter((c) => c.path === "/wifi/station/apply");
const toasts = uiExports.getCapturedToastsForTest();
console.log(JSON.stringify({{
  apply_call_count: applyCalls.length,
  apply_blocked: applyCalls.length === 0,
  toast_requires_confirm: toasts.some((t) => t.includes("confirm")),
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["apply_blocked"] is True
    assert result["apply_call_count"] == 0
    assert result["toast_requires_confirm"] is True


def test_simple_wifi_uplink_apply_with_confirm_calls_station_endpoint() -> None:
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
const manifestPath = process.argv[1].replace(/app\\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
const calls = [];
uiExports.setApiFetchStubForTest(async (path, options) => {{
  calls.push({{ path, body: options.body }});
  if (path === "/routers") {{
    return {{ data: {{ items: [] }}, status: 200 }};
  }}
  if (path === "/wifi/station/apply") {{
    return {{ data: {{ overall: "applied" }}, status: 200 }};
  }}
  return {{ data: {{}}, status: 200 }};
}});
const root = document.createElement("div");
document.body.appendChild(root);
await uiExports.renderSimpleMode(root);
uiExports.goSimpleWizardStep(3, {{ updateHash: false }});
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue";
document.getElementById("simple-uplink-confirm").checked = true;
dom.queryByTestId("simple-uplink-apply", root).click();
await flushUiAsync();
const applyCalls = calls.filter((c) => c.path === "/wifi/station/apply");
console.log(JSON.stringify({{
  apply_call_count: applyCalls.length,
  apply_path: applyCalls.length ? applyCalls[0].path : "",
  confirm_live_apply: applyCalls.length ? applyCalls[0].body.confirm_live_apply : null,
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["apply_call_count"] == 1
    assert result["apply_path"] == "/wifi/station/apply"
    assert result["confirm_live_apply"] is True


def test_simple_connect_step1_advanced_hidden_by_default() -> None:
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface();
document.body.appendChild(connect.section);
const wizardAdvanced = dom.queryByTestId("wizard-draft-advanced-settings", connect.form);
const discoveryAdvanced = dom.queryByTestId("simple-connect-advanced-settings", connect.form);
const collapsedVisible = dom.collectVisibleText(connect.section).toLowerCase();
console.log(JSON.stringify({
  wizard_advanced_closed: wizardAdvanced ? wizardAdvanced.open === false : null,
  discovery_advanced_closed: discoveryAdvanced ? discoveryAdvanced.open === false : null,
  visible_has_host: collapsedVisible.includes("адрес роутера"),
  visible_has_password: collapsedVisible.includes("пароль"),
  visible_has_port: collapsedVisible.includes("порт"),
  visible_has_display_name: collapsedVisible.includes("отображаемое имя"),
  visible_has_discovery_gateway: collapsedVisible.includes("default gateway"),
  visible_has_autodetect_label: collapsedVisible.includes("автообнаружение"),
  password_label_soft: collapsedVisible.includes("one-shot") === false,
  vault_in_body: collapsedVisible.includes("vault"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["wizard_advanced_closed"] is True
    assert result["discovery_advanced_closed"] is True
    assert result["visible_has_host"] is True
    assert result["visible_has_password"] is True
    assert result["visible_has_port"] is False
    assert result["visible_has_display_name"] is False
    assert result["visible_has_discovery_gateway"] is False
    assert result["visible_has_autodetect_label"] is False
    assert result["password_label_soft"] is True
    assert result["vault_in_body"] is False


def test_simple_discovery_multi_candidate_picker_selects_host() -> None:
    """AC-4: UI shows picker when candidates.length > 1; host filled after select."""
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts: null });
document.body.appendChild(connect.section);
uiExports.handleSimpleDiscoveryCandidates(connect, [
  {
    host: "192.168.1.1",
    candidate_origin: "default_gateway",
    identity_state: "unknown",
    source_address: "192.168.1.10",
    route_label: "Ethernet",
  },
  {
    host: "192.168.2.1",
    candidate_origin: "local_subnet_gateway",
    identity_state: "unknown",
    source_address: "192.168.2.10",
    route_label: "Wi-Fi",
  },
]);
const picker = dom.queryByTestId("simple-discovery-candidates", connect.errBox);
const hostEl = connect.form.querySelector("#wizard-host");
const sourceEl = connect.form.querySelector("#wizard-source-address");
const labelEl = connect.errBox.querySelector("label");
const hostBefore = hostEl ? hostEl.value : "";
const sourceBefore = sourceEl ? sourceEl.value : "";
const labelText = labelEl ? labelEl.textContent : "";
dom.queryByTestId("simple-discovery-candidate-select-1", connect.errBox).click();
const hostAfter = hostEl ? hostEl.value : "";
const sourceAfter = sourceEl ? sourceEl.value : "";
const pickerAfter = dom.queryByTestId("simple-discovery-candidates", connect.errBox);
const errVisible = uiExports.collectDomVisibleText(connect.errBox);
console.log(JSON.stringify({
  picker_present: !!picker,
  host_before_empty: hostBefore === "",
  source_before_empty: sourceBefore === "",
  host_after: hostAfter,
  source_after: sourceAfter,
  picker_cleared: pickerAfter === null,
  has_unknown_msg: errVisible.includes("кандидат"),
  label_has_source: labelText.includes("192.168.1.10"),
  label_has_route: labelText.includes("Ethernet"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["picker_present"] is True
    assert result["host_before_empty"] is True
    assert result["source_before_empty"] is True
    assert result["host_after"] == "192.168.2.1"
    assert result["source_after"] == "192.168.2.10"
    assert result["picker_cleared"] is True
    assert result["has_unknown_msg"] is True
    assert result["label_has_source"] is True
    assert result["label_has_route"] is True


def test_simple_discovery_single_candidate_auto_fills_host() -> None:
    """AC-5: single candidate still auto-fills host."""
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts: null });
document.body.appendChild(connect.section);
uiExports.handleSimpleDiscoveryCandidates(connect, [
  {
    host: "192.168.2.1",
    candidate_origin: "default_gateway",
    identity_state: "unknown",
    source_address: "192.168.2.10",
  },
]);
const hostEl = connect.form.querySelector("#wizard-host");
const sourceEl = connect.form.querySelector("#wizard-source-address");
const picker = dom.queryByTestId("simple-discovery-candidates", connect.errBox);
console.log(JSON.stringify({
  host_value: hostEl ? hostEl.value : "",
  source_value: sourceEl ? sourceEl.value : "",
  picker_absent: picker === null,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["host_value"] == "192.168.2.1"
    assert result["source_value"] == "192.168.2.10"
    assert result["picker_absent"] is True


def test_simple_discovery_whitespace_source_address_does_not_overwrite_manual() -> None:
    """Whitespace-only source_address must not overwrite manual bind fields."""
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts: null });
document.body.appendChild(connect.section);
const sourceEl = connect.form.querySelector("#wizard-source-address");
if (sourceEl) sourceEl.value = "10.0.0.5";
const healthSourceEl = document.createElement("input");
healthSourceEl.id = "simple-health-source-address";
healthSourceEl.value = "10.0.0.5";
document.body.appendChild(healthSourceEl);
uiExports.applySimpleDiscoveryCandidateSelection(connect, {
  host: "192.168.2.1",
  candidate_origin: "default_gateway",
  identity_state: "unknown",
  source_address: "   ",
});
console.log(JSON.stringify({
  host_value: connect.form.querySelector("#wizard-host").value,
  source_value: sourceEl ? sourceEl.value : "",
  health_source_value: healthSourceEl.value,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["host_value"] == "192.168.2.1"
    assert result["source_value"] == "10.0.0.5"
    assert result["health_source_value"] == "10.0.0.5"


def test_simple_wifi_uplink_survey_body_without_ssh_pin_is_radio_only() -> None:
    """AC-4: incomplete live (no ssh pin) → survey body {radio} only, no router_id."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({ routerId: "lab-router-1" });
const body = uplink.readSurveyBodyForRadio("WifiMaster0");
console.log(JSON.stringify({
  keys: Object.keys(body).sort(),
  radio: body.radio,
  has_router_id: "router_id" in body,
  has_host: "host" in body,
  has_username: "username" in body,
  has_router_cred: "router_credential_ref_id" in body,
  has_ssh_pin: "ssh_host_key_sha256" in body,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["keys"] == ["radio"]
    assert result["radio"] == "WifiMaster0"
    assert result["has_router_id"] is False
    assert result["has_host"] is False
    assert result["has_username"] is False
    assert result["has_router_cred"] is False
    assert result["has_ssh_pin"] is False


def test_simple_wifi_uplink_survey_body_with_full_live_includes_all_fields() -> None:
    """AC-4: complete live+pin → survey body includes full connection set."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
  ssh_host_key_sha256: "SHA256:deadbeef",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
const body = uplink.readSurveyBodyForRadio("WifiMaster1");
console.log(JSON.stringify({
  radio: body.radio,
  host: body.host,
  username: body.username,
  router_credential_ref_id: body.router_credential_ref_id,
  router_id: body.router_id,
  ssh_host_key_sha256: body.ssh_host_key_sha256,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["radio"] == "WifiMaster1"
    assert result["host"] == "192.168.2.1"
    assert result["username"] == "admin"
    assert result["router_credential_ref_id"] == "credref:mgmt-admin"
    assert result["router_id"] == "lab-router-1"
    assert result["ssh_host_key_sha256"] == "SHA256:deadbeef"


def test_simple_wifi_uplink_ssh_pin_from_step2_dom_when_state_lacks_pin() -> None:
    """Step 2 advanced SSH pin fills completeness gate when state has no pin."""
    script = r"""
const link = uiExports.buildSimpleLinkStepSurface(null);
document.body.appendChild(link.section);
link.advancedDetails.open = true;
document.getElementById("simple-health-ssh-pin").value = "SHA256:from-step2";
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
const body = uplink.readSurveyBodyForRadio("WifiMaster0");
console.log(JSON.stringify({
  has_ssh_pin: body.ssh_host_key_sha256 === "SHA256:from-step2",
  has_host: body.host === "192.168.2.1",
  key_count: Object.keys(body).length,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_ssh_pin"] is True
    assert result["has_host"] is True
    assert result["key_count"] == 6


def test_simple_wifi_uplink_preview_payload_without_ssh_pin_omits_live_fields() -> None:
    """AC-3: incomplete live (no ssh pin) → preview payload has no live connection fields."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({ routerId: "lab-router-1" });
document.body.appendChild(uplink.section);
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue-psk";
document.getElementById("simple-uplink-band").value = "BAND_5GHZ";
const preview = uplink.readPreviewPayload();
console.log(JSON.stringify({
  mode: preview.mode,
  ssid: preview.ssid,
  has_host: "host" in preview,
  has_username: "username" in preview,
  has_router_cred: "router_credential_ref_id" in preview,
  has_router_id: "router_id" in preview,
  has_ssh_pin: "ssh_host_key_sha256" in preview,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["mode"] == "WifiWan"
    assert result["ssid"] == "Venue-WiFi"
    assert result["has_host"] is False
    assert result["has_username"] is False
    assert result["has_router_cred"] is False
    assert result["has_router_id"] is False
    assert result["has_ssh_pin"] is False


def test_simple_wifi_uplink_apply_payload_without_ssh_pin_omits_live_fields() -> None:
    """AC-3: incomplete live (no ssh pin) → apply payload has no live connection fields."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
document.body.appendChild(uplink.section);
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue-psk";
const applyPayload = uplink.readPayload(true);
console.log(JSON.stringify({
  ssid: applyPayload.ssid,
  confirm_live_apply: applyPayload.confirm_live_apply,
  has_host: "host" in applyPayload,
  has_username: "username" in applyPayload,
  has_router_cred: "router_credential_ref_id" in applyPayload,
  has_router_id: "router_id" in applyPayload,
  has_ssh_pin: "ssh_host_key_sha256" in applyPayload,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["ssid"] == "Venue-WiFi"
    assert result["confirm_live_apply"] is False
    assert result["has_host"] is False
    assert result["has_username"] is False
    assert result["has_router_cred"] is False
    assert result["has_router_id"] is False
    assert result["has_ssh_pin"] is False


def test_simple_wifi_uplink_preview_payload_with_full_live_includes_all_fields() -> None:
    """AC-3: complete live+pin → preview payload includes full connection set."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
  ssh_host_key_sha256: "SHA256:deadbeef",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
document.body.appendChild(uplink.section);
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue-psk";
const preview = uplink.readPreviewPayload();
console.log(JSON.stringify({
  ssid: preview.ssid,
  host: preview.host,
  username: preview.username,
  router_credential_ref_id: preview.router_credential_ref_id,
  router_id: preview.router_id,
  ssh_host_key_sha256: preview.ssh_host_key_sha256,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["ssid"] == "Venue-WiFi"
    assert result["host"] == "192.168.2.1"
    assert result["username"] == "admin"
    assert result["router_credential_ref_id"] == "credref:mgmt-admin"
    assert result["router_id"] == "lab-router-1"
    assert result["ssh_host_key_sha256"] == "SHA256:deadbeef"


def test_simple_wifi_uplink_apply_payload_with_full_live_includes_all_fields() -> None:
    """AC-3: complete live+pin → apply payload includes full connection set."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest({
  host: "192.168.2.1",
  username: "admin",
  router_credential_ref_id: "credref:mgmt-admin",
  router_id: "lab-router-1",
  ssh_host_key_sha256: "SHA256:deadbeef",
});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
document.body.appendChild(uplink.section);
document.getElementById("simple-uplink-ssid").value = "Venue-WiFi";
document.getElementById("simple-uplink-credential-ref").value = "credref:venue-psk";
document.getElementById("simple-uplink-confirm").checked = true;
const applyPayload = uplink.readPayload(true);
console.log(JSON.stringify({
  ssid: applyPayload.ssid,
  host: applyPayload.host,
  username: applyPayload.username,
  router_credential_ref_id: applyPayload.router_credential_ref_id,
  router_id: applyPayload.router_id,
  ssh_host_key_sha256: applyPayload.ssh_host_key_sha256,
  confirm_live_apply: applyPayload.confirm_live_apply,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["ssid"] == "Venue-WiFi"
    assert result["host"] == "192.168.2.1"
    assert result["username"] == "admin"
    assert result["router_credential_ref_id"] == "credref:mgmt-admin"
    assert result["router_id"] == "lab-router-1"
    assert result["ssh_host_key_sha256"] == "SHA256:deadbeef"
    assert result["confirm_live_apply"] is True


def test_simple_wifi_uplink_rescan_clears_form_fields() -> None:
    """AC-F1: runScan clears ssid/band/credential_ref/enroll/open state after selection."""
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
function openWarningVisible(root) {{
  function walk(node) {{
    if (!node || typeof node !== "object") return false;
    if (
      node.textContent
      && node.textContent.indexOf("Открытая сеть: подключение без пароля") >= 0
      && node.hidden === false
    ) {{
      return true;
    }}
    for (const child of node.children || []) {{
      if (walk(child)) return true;
    }}
    return false;
  }}
  return walk(root);
}}
uiExports.setApiFetchStubForTest(async (path) => {{
  if (path === "/wifi/site-survey") {{
    return {{
      data: {{
        networks: [
          {{ ssid: "OpenCafe", wpa_mode: "open", signal_quality: "good" }},
        ],
        skipped_row_count: 0,
      }},
      status: 200,
    }};
  }}
  return {{ data: {{}}, status: 200 }};
}});
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({{}});
document.body.appendChild(uplink.section);
await uplink.runScan();
await flushUiAsync();
uplink.selectNetwork(
  {{
    ssid: "OpenCafe",
    wpa_mode: "open",
    survey_radio: "WifiMaster0",
    band_label: "2,4 ГГц",
  }},
  0,
);
document.getElementById("simple-uplink-credential-ref").value = "credref:venue-psk";
document.getElementById("simple-uplink-enroll-password").value = "leftover-enroll-secret";
const beforeRescan = {{
  ssid: document.getElementById("simple-uplink-ssid").value,
  band: document.getElementById("simple-uplink-band").value,
  cred: document.getElementById("simple-uplink-credential-ref").value,
  enroll: document.getElementById("simple-uplink-enroll-password").value,
  open_unsupported_visible: openWarningVisible(uplink.section),
}};
await uplink.runScan();
await flushUiAsync();
console.log(JSON.stringify({{
  before_ssid: beforeRescan.ssid,
  before_band: beforeRescan.band,
  before_cred: beforeRescan.cred,
  before_enroll: beforeRescan.enroll,
  before_open_unsupported_visible: beforeRescan.open_unsupported_visible,
  after_ssid: document.getElementById("simple-uplink-ssid").value,
  after_band: document.getElementById("simple-uplink-band").value,
  after_cred: document.getElementById("simple-uplink-credential-ref").value,
  after_enroll: document.getElementById("simple-uplink-enroll-password").value,
  after_open_unsupported_visible: openWarningVisible(uplink.section),
  preview_enabled: !uplink.previewBtn.disabled,
  apply_enabled: !uplink.applyBtn.disabled,
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["before_ssid"] == "OpenCafe"
    assert result["before_band"] == "BAND_2_4GHZ"
    assert result["before_cred"] == "credref:venue-psk"
    assert result["before_enroll"] == "leftover-enroll-secret"
    assert result["before_open_unsupported_visible"] is True
    assert result["after_ssid"] == ""
    assert result["after_band"] == "BAND_2_4GHZ"
    assert result["after_cred"] == ""
    assert result["after_enroll"] == ""
    assert result["after_open_unsupported_visible"] is False
    assert result["preview_enabled"] is True
    assert result["apply_enabled"] is True


def test_simple_wifi_uplink_open_gate_persists_until_ssid_changes() -> None:
    """AC-F3: open-network lock survives no-op manual edits until SSID changes."""
    script = r"""
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
document.body.appendChild(uplink.section);
uplink.selectNetwork(
  {
    ssid: "OpenCafe",
    wpa_mode: "open",
    survey_radio: "WifiMaster0",
    band_label: "2,4 ГГц",
  },
  0,
);
const ssidEl = document.getElementById("simple-uplink-ssid");
const bandEl = document.getElementById("simple-uplink-band");
function openWarningVisible(root) {
  function walk(node) {
    if (!node || typeof node !== "object") return false;
    if (
      node.textContent
      && node.textContent.indexOf("Открытая сеть: подключение без пароля") >= 0
      && node.hidden === false
    ) {
      return true;
    }
    for (const child of node.children || []) {
      if (walk(child)) return true;
    }
    return false;
  }
  return walk(root);
}
const credEl = document.getElementById("simple-uplink-credential-ref");
const afterSelect = {
  preview_disabled: uplink.previewBtn.disabled,
  apply_disabled: uplink.applyBtn.disabled,
  enroll_disabled: uplink.enrollBtn.disabled,
  open_warning_visible: openWarningVisible(uplink.section),
};
credEl.value = "credref:leftover";
uplink.enterManualOverride();
const afterCredOnly = {
  preview_disabled: uplink.previewBtn.disabled,
  apply_disabled: uplink.applyBtn.disabled,
  enroll_disabled: uplink.enrollBtn.disabled,
  open_warning_visible: openWarningVisible(uplink.section),
};
uplink.enterManualOverride();
const afterNoOpInput = {
  preview_disabled: uplink.previewBtn.disabled,
  apply_disabled: uplink.applyBtn.disabled,
  enroll_disabled: uplink.enrollBtn.disabled,
  open_warning_visible: openWarningVisible(uplink.section),
};
bandEl.value = "BAND_5GHZ";
uplink.enterManualOverride();
const afterBandOnly = {
  preview_disabled: uplink.previewBtn.disabled,
  apply_disabled: uplink.applyBtn.disabled,
  enroll_disabled: uplink.enrollBtn.disabled,
  open_warning_visible: openWarningVisible(uplink.section),
};
ssidEl.value = "OtherNet";
uplink.enterManualOverride();
const afterSsidChange = {
  preview_disabled: uplink.previewBtn.disabled,
  apply_disabled: uplink.applyBtn.disabled,
  enroll_disabled: uplink.enrollBtn.disabled,
  open_warning_visible: openWarningVisible(uplink.section),
};
console.log(JSON.stringify({
  after_select: afterSelect,
  after_cred_only: afterCredOnly,
  after_no_op_input: afterNoOpInput,
  after_band_only: afterBandOnly,
  after_ssid_change: afterSsidChange,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["after_select"]["preview_disabled"] is True
    assert result["after_select"]["apply_disabled"] is True
    assert result["after_select"]["enroll_disabled"] is True
    assert result["after_select"]["open_warning_visible"] is True
    assert result["after_cred_only"]["preview_disabled"] is True
    assert result["after_cred_only"]["apply_disabled"] is True
    assert result["after_cred_only"]["enroll_disabled"] is True
    assert result["after_cred_only"]["open_warning_visible"] is True
    assert result["after_no_op_input"]["preview_disabled"] is True
    assert result["after_no_op_input"]["apply_disabled"] is True
    assert result["after_no_op_input"]["enroll_disabled"] is True
    assert result["after_no_op_input"]["open_warning_visible"] is True
    assert result["after_band_only"]["preview_disabled"] is True
    assert result["after_band_only"]["apply_disabled"] is True
    assert result["after_band_only"]["enroll_disabled"] is True
    assert result["after_band_only"]["open_warning_visible"] is True
    assert result["after_ssid_change"]["preview_disabled"] is False
    assert result["after_ssid_change"]["apply_disabled"] is False
    assert result["after_ssid_change"]["enroll_disabled"] is False
    assert result["after_ssid_change"]["open_warning_visible"] is False


def test_simple_connect_step1_draft_persists_live_connection_state() -> None:
    """AC-1: wizard-draft success persists host/username/credential_ref/router_id."""
    script = r"""
uiExports.setSimpleWizardLiveConnectionForTest(null);
const uplink = uiExports.buildSimpleWifiUplinkStepSurface({});
uiExports.persistSimpleWizardLiveConnectionFromDraft(
  { host: "192.168.2.1", username: "admin" },
  { router_id: "wiz-router-42", credential_ref_id: "credref:mgmt-from-draft" },
  uplink,
);
const lc = uiExports.getSimpleWizardLiveConnectionForTest();
console.log(JSON.stringify({
  host: lc ? lc.host : null,
  username: lc ? lc.username : null,
  router_credential_ref_id: lc ? lc.router_credential_ref_id : null,
  router_id: lc ? lc.router_id : null,
  uplink_router_id: uplink.getRouterId(),
  resolve_null_without_pin: uiExports.resolveSimpleLiveConnectionParams() === null,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["host"] == "192.168.2.1"
    assert result["username"] == "admin"
    assert result["router_credential_ref_id"] == "credref:mgmt-from-draft"
    assert result["router_id"] == "wiz-router-42"
    assert result["uplink_router_id"] == "wiz-router-42"
    assert result["resolve_null_without_pin"] is True


def test_clamp_simple_wizard_step_nan_returns_one() -> None:
    script = r"""
console.log(JSON.stringify({
  nan_clamped: uiExports.clampSimpleWizardStep(NaN),
  infinity_clamped: uiExports.clampSimpleWizardStep(Infinity),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["nan_clamped"] == 1
    assert result["infinity_clamped"] == 1


def test_simple_discovery_zero_candidates_manual_message() -> None:
    """AC-6: zero candidates still prompts manual entry."""
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts: null });
document.body.appendChild(connect.section);
uiExports.handleSimpleDiscoveryCandidates(connect, []);
const errVisible = uiExports.collectDomVisibleText(connect.errBox);
console.log(JSON.stringify({
  has_manual_message: errVisible.includes("Кандидаты не найдены"),
  picker_absent: dom.queryByTestId("simple-discovery-candidates", connect.errBox) === null,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_manual_message"] is True
    assert result["picker_absent"] is True


def test_simple_discovery_degraded_warning_after_candidates() -> None:
    """Degraded host-route diagnostics surface warning after candidate handling."""
    script = r"""
const connect = uiExports.buildSimpleConnectStepSurface({ linkFacts: null });
document.body.appendChild(connect.section);
uiExports.handleSimpleDiscoveryCandidates(connect, [
  {
    host: "192.168.2.1",
    candidate_origin: "local_subnet_gateway",
    identity_state: "unknown",
    source_address: "192.168.2.10",
    route_label: "Wi-Fi",
  },
]);
uiExports.appendSimpleDiscoveryDegradedWarning(connect.errBox, {
  degraded_sources: ["local_subnet_gateway"],
  source_diagnostics: [
    {
      source: "local_subnet_gateway",
      status: "failed",
      reason_code: "timeout",
    },
  ],
});
const errVisible = uiExports.collectDomVisibleText(connect.errBox);
console.log(JSON.stringify({
  host_filled: connect.form.querySelector("#wizard-host").value === "192.168.2.1",
  has_degraded_warning: errVisible.includes("Не удалось прочитать локальные маршруты"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["host_filled"] is True
    assert result["has_degraded_warning"] is True


def test_simple_discovery_autodetect_button_label_in_flight_and_restore() -> None:
    """F-3: auto-detect button shows in-flight label and restores after fetch."""
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
const manifestPath = process.argv[1].replace(/app\\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
let releaseDiscovery;
const discoveryGate = new Promise((resolve) => {{
  releaseDiscovery = resolve;
}});
uiExports.setApiFetchStubForTest(async (path) => {{
  if (path === "/routers") {{
    return {{ data: {{ items: [] }}, status: 200 }};
  }}
  if (path === "/lab/router-discovery") {{
    await discoveryGate;
    return {{
      data: {{ candidates: [], degraded_sources: [], source_diagnostics: [] }},
      status: 200,
    }};
  }}
  return {{ data: {{}}, status: 200 }};
}});
const root = document.createElement("div");
document.body.appendChild(root);
await uiExports.renderSimpleMode(root);
const btn = dom.queryByTestId("simple-connect-autodetect", root);
const labelBefore = btn ? btn.textContent : "";
if (btn) btn.click();
await flushUiAsync();
const labelInFlight = btn ? btn.textContent : "";
const disabledInFlight = btn ? btn.disabled : null;
releaseDiscovery();
await flushUiAsync();
const labelAfter = btn ? btn.textContent : "";
console.log(JSON.stringify({{
  label_before: labelBefore,
  label_in_flight: labelInFlight,
  label_after: labelAfter,
  disabled_in_flight: disabledInFlight,
  disabled_after: btn ? btn.disabled : null,
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["label_before"] == "Автообнаружение"
    assert result["label_in_flight"] == "Автообнаружение…"
    assert result["label_after"] == "Автообнаружение"
    assert result["disabled_in_flight"] is True
    assert result["disabled_after"] is False
