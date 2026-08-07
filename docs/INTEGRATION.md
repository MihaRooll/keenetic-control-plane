# Router Control — интеграция в сторонний FastAPI-сервис

## For agents

| Topic | Rule |
|---|---|
| When to read | Перед встраиванием `router_control` в сторонний Python 3.11 / FastAPI сервис (не `router_control_host`) |
| Public entry | `RouterControlConfig` + `build_runtime` из пакета `router_control`; фабрики `create_*_runtime` — низкоуровневый dispatch |
| Adapter modes | `fake` (без БД), `offline` (SQLite + FakeAdapter), `live` (SQLite + DPAPI vault; **без** поля `adapter` на runtime) |
| Paths | `db_path` (offline+live), `secrets_root` (live); artifact-staging — **только offline**, из `db_path.parent`; encrypted durable roots — **только offline** при `durable_backup_artifacts=True` (facade flag **не** экспонирует); live **не** настраивает artifact roots — см. §4 |
| Gates today | A open RO observe/inventory; B `completed_failed`; C/D closed; **WriteCertified NOT claimed** |
| Writes | Apply/VPN/routes/zones/interface save — Gate B WriteCertified + exact T4 Human Gate Packet |
| Secrets | `HUB_ADMIN_PASSWORD` env для hub_admin auth в reference host; DPAPI на live; `MemoryVault` только tests/offline |
| Verify | `pytest tests/test_integration_facade.py -q` после изменений facade/docs |

---

## 1. Установка и extras

Базовое ядро (stdlib-only runtime):

```bash
pip install -e .
```

FastAPI dev-host и интеграционные примеры с HTTP:

```bash
pip install -e ".[host]"
```

SSH/tunnel probe для hardware lane (Paramiko):

```bash
pip install -e ".[hardware]"
```

Полный dev-набор (pytest, ruff, mypy, httpx):

```bash
pip install -e ".[dev,host]"
```

---

## 2. Public API

### Facade

```python
from pathlib import Path

from router_control import RouterControlConfig, build_runtime

config = RouterControlConfig(
    adapter_mode="offline",  # "fake" | "offline" | "live"
    db_path=Path("data/router-control.sqlite3"),
    secrets_root=Path("data/secrets"),  # live only
    router_id=None,  # fake only; None → factory default
    fingerprint_digest=None,  # fake only
)
runtime = build_runtime(config)
```

| Mode | Factory | Runtime type | `adapter` field |
|---|---|---|---|
| `fake` | `create_fake_runtime` | `FakeRuntime` | `FakeRouterAdapter` |
| `offline` | `create_offline_runtime` | `OfflineRuntime` | `FakeRouterAdapter` |
| `live` | `create_live_runtime` | `LiveRuntime` | **отсутствует** |

Дополнительные экспорты пакета: `create_fake_runtime`, `create_offline_runtime`, `create_live_runtime`, `OfflineRuntime`, `LiveRuntime`, `MemoryVault`.

### RouterControlPort (10 методов)

Адаптер (`runtime.adapter` для fake/offline) реализует `RouterControlPort`:

| Method | Purpose |
|---|---|
| `check_identity(expected)` | Сравнение fingerprint digest |
| `get_capabilities(router_id)` | Capability snapshot |
| `observe(router_id)` | Read-only inventory / observation |
| `create_backup(router_id, operation_id)` | Pre-mutation backup |
| `begin_fail_safe(router_id)` | Fail-safe session arm |
| `apply_plan(plan)` | Sealed change plan dispatch |
| `read_back(router_id, plan_id)` | Post-apply state read-back |
| `verify_postconditions(plan, read_back)` | Postcondition check |
| `save_configuration(router_id)` | Persist running config |
| `compensate(router_id, backup)` | Rollback from backup |

Опционально адаптеры могут реализовать `ApplyContinuationPort.poll_apply_continuation(router_id, plan_id, continuation_token)` для async apply continuation (fake — да; live adapters — deny-by-default).

Пример read-only observe (fake/offline):

```python
from router_control import RouterControlConfig, build_runtime
from router_control.domain.ids import RouterId

runtime = build_runtime(RouterControlConfig(adapter_mode="fake"))
obs = await runtime.adapter.observe(RouterId("router-fake-001"))
```

---

## 3. Third-party FastAPI mount (pattern)

Reference prototype: `router_control_host` монтирует API под **`/api/router-control/v1`** ([`docs/contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md)). Auth boundary — env **`HUB_ADMIN_PASSWORD`** (значение задаёт operator; не хранить в коде).

Минимальный паттерн для стороннего Hub:

```python
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request

from router_control import RouterControlConfig, build_runtime


def router_control_config() -> RouterControlConfig:
    return RouterControlConfig(
        adapter_mode="offline",
        db_path=Path("data/router-control.sqlite3"),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.router_control = build_runtime(router_control_config())
    yield


app = FastAPI(lifespan=lifespan)


def get_runtime(request: Request):
    return request.app.state.router_control


@app.get("/api/router-control/v1/health")
async def health(runtime=Depends(get_runtime)):
    return {"adapter_mode": "offline", "db_path": str(runtime.db_path)}
```

Для полного contract-aligned surface можно `include_router` из `router_control_host` (commissioning, presets, worker) — это отдельный шаг Hub integration; facade покрывает только composition bootstrap.

Live mode в lifespan:

```python
RouterControlConfig(
    adapter_mode="live",
    db_path=Path("data/router-control.sqlite3"),
    secrets_root=Path("data/secrets"),
)
```

`LiveRuntime` не имеет `.adapter`; read-only observe на hardware идёт через host certification + pinned probe (`router_control_host`), не через прямой adapter на runtime.

---

## 4. Path config и ограничения

### Настраивается через facade / factories

| Parameter | Used by | Default when `None` |
|---|---|---|
| `db_path` | `offline`, `live` | Package default (`DEFAULT_DB_PATH` in persistence) |
| `secrets_root` | `live` | `data/secrets` |
| `router_id`, `fingerprint_digest` | `fake` | Factory defaults (`router-fake-001`, `digest:identity:fake-001`) |

`RouterControlConfig` / `build_runtime` пробрасывают только эти поля; дополнительной wiring поверх composition нет.

### Known limitation: artifact roots

| Runtime | Artifact staging / encrypted | Notes |
|---|---|---|
| **Offline** (`create_offline_runtime`, `build_runtime` с `adapter_mode="offline"`) | `db_path.parent / "artifact-staging"` всегда | Encrypted durable roots (`artifact-staging-durable`, `artifact-encrypted`) — **только** если `durable_backup_artifacts=True` на `create_offline_runtime`; иначе backup publisher in-memory (`FakeBlobStore`) |
| **Live** (`create_live_runtime`, `build_runtime` с `adapter_mode="live"`) | **Не настраиваются** | Composition не подключает artifact-staging / artifact-encrypted для live runtime |

Пути staging/encrypted **не** являются параметрами фабрик или facade. Public facade **не** экспонирует `durable_backup_artifacts` (composition default: `False`). Чтобы сменить offline staging root без прямого вызова composition — только перенести родительский каталог `db_path`; для encrypted durable roots нужен низкоуровневый `create_offline_runtime(..., durable_backup_artifacts=True)` (вне scope integration facade).

---

## 5. Сегодня без WriteCertified

| Capability | Status |
|---|---|
| Gate A RO observe / inventory | Allowed on certified exact tuple (dedicated lab policy) |
| Offline planning / presets / commissioning API | `write_ready=false` always in offline assess paths |
| Sealed operator CLIs (interface/save/fail-safe) | Validate-default offline; live `--execute` только exact T4 |
| Apply, VPN shapes, routes, zones | **Gated** — требуют Gate B **WriteCertified** (не достигнут; B = `completed_failed`) |

Не утверждайте WriteCertified без явного SSOT evidence и human gate closeout.

---

## 6. Security и hardware gates

| Gate | Status (2026-07-23 SSOT) | Implication |
|---|---|---|
| A | Open ReadOnlyCertified (exact NC-1812 tuple) | RO observe/probe/re-cert only |
| B | `completed_failed` | No standing write certification |
| C | Closed | No dedicated lab write window |
| D | Closed | No production write window |

Vault:

- **Live host:** `WindowsDpapiVault` under `secrets_root` (Windows DPAPI).
- **Tests / offline:** `MemoryVault` — in-memory only, not for production secrets.

Rules:

- No passwords, private keys, preshared keys, raw sessions, or startup-config in code, docs, fixtures, or logs.
- Every live mutation/reboot/install/reset/write trial requires an **exact T4 Human Gate Packet** per campaign — program authorization is not standing write approval ([`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)).

---

## Related docs

- [`docs/contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) — HTTP surface
- [`docs/contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) — gate semantics
- [`docs/DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — lab ownership and T4
- [`router_control_host/app.py`](../router_control_host/app.py) — reference lifespan wiring
