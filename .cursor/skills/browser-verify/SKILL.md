---
name: browser-verify
description: Проверка UI через нативный Cursor Browser MCP; local IDE vs Cloud Agents; Human Gate для auth и недоверенных origin; без хранения credentials.
---

# browser-verify

## Когда

- Нужна визуальная или DOM-проверка после change/build
- Smoke/e2e на localhost или staging без полноценного test runner
- Сравнение local IDE Browser vs Cloud Agents limitations

## Шаги

1. Прочитай `docs/project-environment.md` и `docs/cursor-native-controls.md` (workspace root; в plugin/Essential — product `docs/`).
2. **Surface:** local IDE — native Browser MCP; Cloud Agents — только если origin доступен из cloud; иначе Human Gate.
3. **Human Gate (обязательно)** перед navigation/actions если:
   - origin требует login / OAuth / cookies / SSO
   - origin недоверенный (не localhost, не approved staging)
4. Используй Browser MCP snapshot → deliberate action → re-snapshot (см. server instructions).
5. Зафиксируй findings с path/evidence; не сохраняй пароли, tokens, session cookies в repo/skills.

## Local IDE vs Cloud Agents

| | Local IDE | Cloud Agents |
|---|-----------|--------------|
| localhost | Usually OK | Often **no** — use deployed preview or Human Gate |
| Auth sites | Human Gate first | Human Gate + explicit user session |
| Credentials | Never store in skill/chat logs | Same |

## Не делай

- Не вводи credentials в Browser без явного human approval
- Не пиши secrets в screenshots paths или markdown
- Не обходи Human Gate для production mutations

## Verify

- Snapshot/screenshot evidence attached to verification record
- No credential strings in output
