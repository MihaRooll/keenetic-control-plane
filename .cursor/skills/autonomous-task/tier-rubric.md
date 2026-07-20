# Tier rubric

Сначала проверь T4 overrides, затем Minimum T3. Только если они не сработали, выбирай минимальный T0–T2. Повышение tier требует одной строки evidence.

| Tier | Признаки | Pipeline |
|------|----------|----------|
| T0 | Один локальный файл, однозначный diff, сильный oracle | Composer + shell verify |
| T1 | Обычный bug/small feature, ограниченный scope, хорошие tests | Composer + verifier |
| T2 | Multi-file/module/refactor, слабее oracle, нужен reviewed plan | Grok orchestrator pipeline |
| T3 | Security/auth/public API/protocol/concurrency/архитектурная развилка | T2 + Sol pre-write |
| T4 | Destructive/external/irreversible/high-impact human decision | Human gate |

## Score (tie-breaker)

По 0–2: blast radius, ambiguity, coupling, irreversibility/security, oracle weakness.

- 0–1 → T0
- 2–3 → T1
- 4–10 → T2

Score только различает T0–T2. T3 требует признака из Minimum T3; T4 — только явного T4 override. Высокий score сам по себе не вызывает Sol/human gate.

## Hard overrides

### Minimum T3

- authentication / authorization / security-sensitive product code;
- public API, protocol or persistent data-model contract;
- concurrency/race correctness;
- архитектурное решение с несколькими необратимо дорогими вариантами.

### T4

- secrets or credentials;
- payments/billing mutation;
- production deploy or production database change;
- data loss, destructive reset/delete, irreversible migration;
- `git push`, publish, release, merge or other external write;
- user/account/cloud mutation with material blast radius.

## Default-down checks

- Не повышай tier только потому, что доступно много дешёвых токенов.
- Не вызывай Sol «для уверенности» на T0–T2.
- Если требования materially ambiguous, Main задаёт один focused question; ambiguity не маскируется swarm’ом.
