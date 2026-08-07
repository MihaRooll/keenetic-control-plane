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

## Восстановление после потери MCP (смена аккаунта Cursor)

Симптомы: `cursor-ide-browser` отсутствует в списке серверов; `plugin-browse-browser` падает с
`ENOENT`/`EINVAL`/`EACCES`/`"Not connected"`. По наблюдению оператора коррелирует со сменой
аккаунта Cursor (не подтверждено механически как причина, но это единственная замеченная
переменная). Полный root-cause и симптом→причина→фикс таблица: `docs/OPERATOR_BROWSER_MCP_RECOVERY.md`.

1. Не патчи вручную по памяти — запусти скрипт: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\repair-browser-mcp.ps1 -SelfTest`. Он идемпотентен (безопасно перезапускать) и сам проверяет результат сквозным self-test.
2. Если задача уже сложная/шумит в текущем чате, или нужно не занимать основной контекст — вынеси восстановление в отдельный `Task` subagent (`subagent_type: shell`) с прямой ссылкой на этот раздел и на `docs/OPERATOR_BROWSER_MCP_RECOVERY.md`, попросив вернуть только итоговый статус (OK/FAIL + что осталось сделать оператору).
3. Если скрипт вносил изменения (`changed=true` в выводе) — требуется **один ручной шаг оператора**: переключить `plugin-browse-browser` в `Settings → MCP` (выкл/вкл) или сделать `Reload Window`. Cursor не респавнит упавший MCP-процесс сам — попроси об этом явно, это не обходится автоматизацией.
4. После шага оператора — проверь **реальным вызовом MCP-инструмента** (`browser_status`/`browser_navigate`), а не только результатом self-test скрипта (self-test работает мимо MCP-обёртки Cursor).
5. Если `plugin-browse-browser` физически не установлен или скрипт говорит `FAIL` с сообщением о дрейфе версии плагина — проверь `cursor-ide-browser` прямым вызовом инструмента (его наличие сессионное, может появляться/пропадать без видимой причины) прежде чем считать браузер недоступным.

## Не делай

- Не вводи credentials в Browser без явного human approval
- Не пиши secrets в screenshots paths или markdown
- Не обходи Human Gate для production mutations
- Не патчи `plugin-browse-browser` вручную построчно по памяти — используй `scripts/repair-browser-mcp.ps1`, иначе легко повторить уже известную ошибку (наивный патч socket-пути без отключения `fs.access`-проверки на Windows роняет демон необработанным `EPIPE`, см. §M-49)

## Verify

- Snapshot/screenshot evidence attached to verification record
- No credential strings in output
