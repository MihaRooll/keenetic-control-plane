# ADR-004: Product and capability scope

- Status: Accepted
- Date: 2026-07-19
- Scope: first supported product, capability order and legacy cutover

## Context

Router Control должен расти до VPN, маршрутов, TrafficDiscovery, Wi-Fi/LAN
presets, SIM uplink и multi-router. Попытка реализовать все capabilities сразу
заморозит непроверенные RCI assumptions в API и domain model.

Первая hardware target уже выбрана: **Netcraze Ultra NC-1812**. На устройстве
наблюдалась raw version string `5.01`, но exact NDMS release/build/channel,
installed components и AWG semantics ещё не сертифицированы.

Legacy WPF/PowerShell уже умеет собирать IP, накапливать `/24` profiles и
отправлять routes на старый Keenetic-контур. Он остаётся production fallback,
пока Python implementation не достигнет parity.

## Decision

### Certified target

Первая write certification выполняется только для точного tuple:

`NC-1812 + hardware revision + NDMS build/channel + component-set digest`.

Другой model/firmware tuple доступен только для detect/read-only до прохождения
собственной compatibility lane. Capability discovery и stable `RouterId`
закладываются сразу, но multi-vendor writes не входят в v1.

### Capability order

1. Offline Python core, fake adapter, persistence и jobs.
2. Read-only identity/capability/health NC-1812.
3. DPAPI credentials и recovery foundations.
4. AmneziaWG profile import, greenfield create, apply/switch и verify.
5. Managed routes и scale certification.
6. TrafficDiscovery как отдельный bounded context.
7. NetworkPolicy для Guest/Promo/Staff/Admin.
8. Интеграция в `module_3.0`.
9. HTTPS/event infrastructure, RMM approval и field cutover.

Routes, Capture и Wi-Fi отсутствуют в OpenAPI v0. Raw RCI endpoint не
предоставляется.

### VPN scope

- v1 принимает только `AmneziaWG`.
- Unsupported/unknown fields fail closed.
- Profile catalog не имеет искусственного product limit.
- Profile artifact и router assignment — разные entities.
- Первый deployment preset допускает один active AWG assignment на router.
  Это policy, а не универсальный domain invariant и не hard-code
  `Wireguard0`.
- Firmware/components в v1 только обнаруживаются. Install/update/reboot через
  component manager выполняет оператор вне Router Control.

### Route scale

Internal stress target — 5000 managed routes. Netcraze публикует лимит 1024
строк для batch-import file, но не общий active-route limit. Поэтому 5000 —
unsupported benchmark, не product promise.

Production ceiling устанавливается только после trials 100/1000/5000 с
измерением plan/apply/read-back/save/reboot/restore и повторной проверкой
baseline. Если 5000 не проходит, система фиксирует измеренный ceiling и
пересматривает aggregation/policy-routing strategy; она не скрывает failure.

### TrafficDiscovery

TrafficDiscovery реализуется отдельным Python bounded context. Он создаёт
timestamped evidence и `RouteProposal`, но не изменяет router напрямую.
Default — operator review. Auto-apply разрешается только для явно marked
trusted policy с теми же plan, idempotency, ownership и verification gates.

До parity `TrafficMonitorGui` и `Monitor-CursorNetwork.ps1` остаются working
strangler path. Совместное управление одним resource двумя writers запрещено.

### Event network and availability

Target preset использует четыре zones: Guest, Promo, Staff, Admin/Server.
Guest LAN-only получает только локальную HTTPS order page по QR/signage.
Router Control degraded/disabled не блокирует kiosk, board, printing или Hub.
Accepted offline window — 1–3 дня.

## Consequences

- API v0 остаётся малым и не обещает будущие resources до их certification.
- NC-1812-specific locators и historical FI endpoint не попадают в core.
- AWG writes остаются blocked до hardware gate, даже если parser принимает
  profile.
- Route scale становится измеримым release criterion.
- Capture нельзя использовать как hidden direct-push path.
- Legacy удаляется только после parity, restore rehearsal, field acceptance и
  explicit cutover.

## Rejected alternatives

- Сертифицировать всю Keenetic/Netcraze line одновременно.
- Включить standard WireGuard/OpenVPN «на будущее» без use case.
- Сразу публиковать routes/capture/Wi-Fi в OpenAPI v0.
- Считать 5000 vendor-supported limit.
- Использовать `Wireguard0` или endpoint IP как domain identity/default.
- Удалить legacy сразу после появления Python skeleton.

## Compliance

Decision соблюдается, если:

- [`COMPATIBILITY.md`](../COMPATIBILITY.md) хранит exact tuple и gates;
- OpenAPI v0 не содержит routes/capture/Wi-Fi;
- unknown capability blocks writes;
- one-active assignment остаётся deployment policy;
- TrafficDiscovery выдаёт proposals;
- STATUS не продвигает hardware writes до certification;
- cutover требует parity и field rehearsal.
