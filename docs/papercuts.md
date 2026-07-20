# Papercuts — complaint box для агентов

> **AI-first.** Источник: SRC-011 — [treygoff24/papercuts](https://github.com/treygoff24/papercuts) · идея: [Steve Ruiz / X](https://x.com/steveruizok/status/2075303919664734295).

## For agents

**Когда читать:** трение в работе (мертвый tool call, битая ссылка, лживый doc, footgun config); настройка harness; review backlog UX репо.

**Применяй (если `papercuts` есть в PATH):**
- Работай **из git-репо** (тогда лог → `.papercuts.jsonl` в корне)
- Поймал friction → сразу:  
  `papercuts add "<что случилось и что бы предотвратило>" --tag <area>`
- Не останавливай задачу — залогируй и продолжай
- Severity: `minor` (default) | `major` | `blocker`
- Сбой команды: добавь `--cmd`, `--exit`, `--stderr-file` (не сырой env dump)
- Контракт: один раз `papercuts schema`
- Периодически / по просьбе: `papercuts list --format md` → чинить повторяющееся

**Windows footgun:** вне git-репо CLI пишет в `~/.papercuts/` и требует `HOME`. В PowerShell часто нет `HOME` → ошибка `cannot resolve the home directory`. Фикс:

```powershell
$env:HOME = $env:USERPROFILE
# из корня git-репо:
papercuts add "…" --tag harness
# или явно:
papercuts --file .\.papercuts.jsonl add "…" --tag harness
```

Постоянно (один раз):  
`[Environment]::SetEnvironmentVariable("HOME", $env:USERPROFILE, "User")`  
→ новый терминал.

**Если CLI не установлен:** shim `scripts/papercuts.ps1` или предложи `cargo install papercuts`.

**Не делай:** глотать ошибки молча; класть секреты/полный env в evidence; rewrite `.papercuts.jsonl` руками (только append через CLI).

**Вердикт:** высокая ценность для harness — living feedback loop на docs/tools/cwd (compound после triage).

## Автоматический режим (в этом репо)

| Hook | Файл | Поведение |
|------|------|-----------|
| `sessionStart` | `.cursor/hooks/session-start.ps1` | HOME/context reminder |
| `afterShellExecution` | `.cursor/hooks/after-shell-papercuts.ps1` | exit≠0 → auto `add` (≤8/день, dedupe) |
| `stop` | `.cursor/hooks/stop-papercuts-nudge.ps1` | раз/день nudge если есть open cuts |

Конфиг: `.cursor/hooks.json`. State: `.cursor/hooks/state/` (gitignore).

Авто **не заменяет** ручной `add` для «лживых docs» и отсутствующих инструментов без failed shell.

При bootstrap в продукт hooks копируются вместе с harness (`docs/bootstrap-scaffold.md`).

---

## Суть

Агенты постоянно упираются в мелочи и **молча обходят** их — сигнал теряется. Papercuts = однострочный «ящик жалоб» → JSONL в репо → человек/агент чинит первопричины.

Идея: Steve Ruiz ([твит](https://x.com/steveruizok/status/2075303919664734295)); реализация CLI: [treygoff24/papercuts](https://github.com/treygoff24/papercuts) (MIT, Rust).

## Install

### Вариант A — shim в этом репо (без Rust, Windows)

Уже есть: `scripts/papercuts.ps1` / `scripts/papercuts.cmd`.

```powershell
# из корня репо
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/papercuts.ps1 add "пример трения" -Tag tooling
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/papercuts.ps1 list -Format md
```

Агенты в этом репо должны использовать shim, пока нет настоящего CLI.

### Вариант B — официальный CLI (нужен Rust)

Готовых `.exe` в Releases обычно нет → `cargo install papercuts`.

Если `cargo` не найден / toolchain ломается:

1. Открой **PowerShell от Администратора**
2. `winget install --id Rustlang.Rustup -e`
3. Новый терминал → `rustup default stable` → `cargo -V`
4. `cargo install papercuts`
5. Проверь: `papercuts --help`

Скрипт-помощник: `scripts/install-rust-papercuts.ps1` (может упасть без Admin / из‑за AV на rename downloads).

Альтернатива: https://rustup.rs

**Уже есть рабочий cargo:**
```bash
cargo install papercuts
```

## Команды

| Команда | Зачем |
|---------|--------|
| `papercuts add "…"` | Записать cut (`log`, stdin `add -`) |
| `papercuts list` | Открытые cuts (JSON) |
| `papercuts list --format md` | Дайджест для людей |
| `papercuts resolve pc_9f2c` | Закрыть (prefix id ok; можно несколько) |
| `papercuts schema` | Полный machine contract |
| `papercuts doctor` | Валидация лога |

Опции `add`: `--tag`, severity, `--cmd`, `--exit`, `--stderr-file`, `--evidence`.

## Хранение

- Default: `.papercuts.jsonl` в корне репо (append-only journal)
- В git diff / PR — видно команде
- Merge: в `.gitattributes` → `.papercuts.jsonl merge=union`
- Private: gitignore или `PAPERCUTS_FILE`; вне git → `~/.papercuts/log.jsonl`
- Нет сервера, telemetry; concurrency-safe (lock + atomic append)

## Agent-first контракт

- stdout = только data (JSON envelope)
- stderr = structured errors + `suggested_fix`
- Exit codes документированы (0 ok · 2 usage · 65 bad input · 66 not found · 70 internal · 74 I/O · 75 lock retry · 77 perm · 78 config)
- Пустой list = exit 0

## Связь с harness

| Идея | Куда у нас |
|------|------------|
| Complaint → fix harness | compound в rules/skills/docs после triage |
| Living signal | лучше static бенчмарков (см. SRC-002) |
| AGENTS snippet | секция Papercuts в `AGENTS.md` |
| Review loop | skill `review-papercuts` / session checklist |

## Чеклист внедрения в проект

- [ ] `cargo install papercuts`
- [ ] Snippet в `AGENTS.md`
- [ ] `.gitattributes`: `merge=union` (если коммитим лог)
- [ ] Решить: commit `.papercuts.jsonl` vs private
- [ ] Раз в неделю: `papercuts list --format md` → fix top cuts

---

## Источник

- https://github.com/treygoff24/papercuts  
- https://x.com/steveruizok/status/2075303919664734295  
- SRC-011 (реестр источников — только в cursor-project-toolkit Full surface)
