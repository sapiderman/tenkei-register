# Tenkei Register Backend

**Repo**: `sapiderman/tenkei-register` | **Language**: Go 1.26.6 | **License**: MIT

## AI Rules

1. Write "Boring Go". Clarity and security over brevity.
2. Use the existing stack (`chi`, `zerolog`, `bun`, `viper`). No new deps without justification.
3. Never log passwords, tokens, WhatsApp numbers, or emergency contacts.
4. Never `panic()` in app code. Return wrapped errors.
5. No global state. Use dependency injection.
6. Write unit tests for all new handlers, middleware, and database functions. Aim for 100% coverage on new code.
7. Read and load the [Kaparthy Guidelines](https://github.com/sapiderman/andrej-karpathy-skills/blob/main/skills/karpathy-guidelines/SKILL.md) before suggesting changes or writing any code. This is your compass for code quality and style.
8. Minimize DB round-trips and in-process CPU. The app runs on Cloud Run (metered per-request) and the DB on Neon free-tier compute (metered, scale-to-zero). Prefer one batched query over a loop of queries; push filtering/count/pagination into SQL; avoid heavy computes in the request path. See [Resource Constraints](#resource-constraints-free-tier).

## Tech Stack

- **Router**: `chi/v5` + `chi/httprate` (rate limiting)
- **DB**: PostgreSQL via `uptrace/bun` + `pgdriver`
- **Auth**: `golang.org/x/crypto/bcrypt` | session cookies (server-side, DB-backed)
- **Validation**: `go-playground/validator/v10`
- **Logging**: `zerolog` | **Config**: `spf13/viper`
- **Graceful shutdown**: `golang.org/x/sys/unix` (SIGTERM, SIGINT, SIGQUIT)

## Project Structure

```
├── main.go
├── config/                  # Viper config (env vars + YAML)
├── internal/
│   ├── server.go            # StartServer, ServeWith (graceful shutdown)
│   ├── http.go              # NewHTTPHandler, middleware wiring
│   ├── auth/                # Login, session, profile, shared session/role middleware
│   ├── register/           # Registration (JSON)
│   ├── admin/              # Member administration (list/view/edit/verify/role)
│   ├── types/              # Shared bun models: User, Audit, Ranks, parse helpers
│   ├── database/           # DB connection + query logging hook
│   ├── middleware/          # XCFBypass, AccessLog
│   └── server/             # JSON response helpers (WriteJSON, DecodeJSON, DecodeAndValidate)
├── migrations/
├── .devcontainer/           # Go + PostgreSQL dev environment
├── Dockerfile               # Multi-stage build (scratch)
└── Makefile
```

## Routes

| Method | Path | Middleware | Purpose |
| ------ | ---- | ---------- | ------- |
| POST | `/v1/register/` | XCFBypass + rate-limit (5/min/IP) | New member registration (JSON) |
| GET | `/v1/register/count` | XCFBypass + rate-limit (5/min/IP) | Total registered user count |
| POST | `/v1/auth/login` | XCFBypass + rate-limit (10/min/IP) | Session login (JSON) |
| GET | `/v1/auth/profile` | XCFBypass + session cookie | View profile |
| PUT | `/v1/auth/profile` | XCFBypass + session cookie | Update profile |
| POST | `/v1/auth/logout` | XCFBypass + session cookie | Invalidate session |
| POST | `/v1/auth/logout-all` | XCFBypass + session cookie | Revoke all sessions (compromise response) |
| POST | `/v1/auth/password` | XCFBypass + session cookie | Change own password (re-verifies current; invalidates other sessions) |
| GET | `/v1/admin/users` | XCFBypass + session + role>=2 | List members (viewer-scoped, paginated, summary only) |
| GET | `/v1/admin/users/:id` | XCFBypass + session + role>=2 | View a member's full profile (admin: new/user only; superuser: anyone) |
| PUT | `/v1/admin/users/:id` | XCFBypass + session + role>=2 | Edit a member's profile (same whitelist as self-profile; role absent) |
| POST | `/v1/admin/users/:id/verify` | XCFBypass + session + role>=2 | Verify a member (new -> user); no session invalidation |
| PUT | `/v1/admin/users/:id/role` | XCFBypass + session + role>=3 | Set a member's role (superuser only; atomic last-superuser guard) |
| GET | `/health` | None (before XCFBypass) | Liveness probe |

## Authorization Model

Every account has one role, stored on `users.role` (NOT NULL, CHECK-constrained to four values) and resolved per request via a `sessions ⋈ users` join in session validation — so a role change takes effect on the *next* request, with no session reissue.

| Role | Level | Can do |
| ---- | ----- | ------ |
| `new` | 0 | Self-service profile only (soft gate; same as today) |
| `user` | 1 | Self-service profile |
| `admin` | 2 | + list/view/edit/verify members (`new`/`user` scope) |
| `superuser` | 3 | + full scope over all members + role management |

Authorization is one middleware, `roleRequired(minLevel)`, with **`>=`** semantics (no `==` gate): it admits at-or-above and returns `403` below. `sessionRequired` runs first and supplies the `401` for no/invalid session. Self-profile endpoints (`/v1/auth/profile`) carry **no** minimum-level requirement — a `new` member self-serves exactly as before. Single source of truth: `internal/types/roles.go`.

### First-superuser bootstrap

There is **no endpoint, flag, or migration** that creates the first superuser — by design, so the privilege can only ever come from an operator with database access. To seed it, run this against the production database:

```sql
UPDATE users SET role = 'superuser' WHERE email = 'you@dojo.example';
```

That account's next request (the role is read live from the user row) gains superuser capabilities. The last-superuser guard (Phase B5) then prevents demoting the final superuser to zero.

## Middleware Stack (in order)

Applied in `internal/http.go`. Order matters.

1. `RequestID` → 2. `Recoverer` → 3. `AccessLog` → 4. `Heartbeat("/health")` → 5. `XCFBypass` → 6. `Timeout(60s)`

- `/health` bypasses `XCFBypass` (check #4 before #5).
- **Auth endpoints** additionally use `sessionRequired` middleware (inside `auth.NewRouter`).
- **Admin endpoints** (`/v1/admin/*`) use `sessionRequired` + `roleRequired(>=2)`; the role-management route additionally stacks `roleRequired(>=3)`. Role is resolved per request via the `sessions ⋈ users` join in `SessionStore.Validate`.
- Turnstile is **not** middleware — it's verified inline in the register handler (`verifyTurnstileResponse`), gated by `TENKEI_SERVER_TURNSTILE_ENABLED`.

## Key Architecture Decisions

- **JSON-only endpoints**: All routes accept and return JSON. Input strings are trimmed only; HTML escaping happens at the frontend renderer (escaping at storage corrupts data and is skipped inconsistently).
- **Anti-enumeration**: Login returns identical `401 "invalid credentials"` for wrong password and nonexistent user.
- **Session cookies**: `HttpOnly`, `Secure` in production, `SameSite=Lax`, `Path=/` (must reach both `/v1/auth` and `/v1/admin`). Only `SHA-256(token)` is stored server-side — a DB leak yields no usable sessions. Expired rows are purged opportunistically at login (no background workers on Cloud Run).
- **PII masking**: Login failures log `mask(identifier)` only — never raw email/WhatsApp.
- **Connection pool**: 25 max open, 10 idle, 5-minute lifetime.
- **Server timeouts**: Read/Write 10s, Idle 120s, ReadHeaderTimeout from config (default 5s).

## Resource Constraints (Free Tier)

Both the app (Cloud Run) and DB (Neon Postgres free tier) run on metered/scaling compute. Optimize for few round-trips and cheap request paths — see AI Rule 8.

| Resource | Limit | Implication |
| --- | --- | --- |
| Cloud Run CPU | Billed per request | No background workers/tickers (instance dies on scale-to-zero). Scheduled cleanup must be an **external trigger** (e.g. Cloud Scheduler → protected endpoint), never an in-process goroutine. |
| Neon compute | 100 CU-hours/month | DB sleeps after 5 min idle. Keep queries cheap; `pg_cron` only runs while awake, so it is **not** reliable here. |
| Neon storage | 0.5 GB / project | Bounded but slow-growing: `sessions`/`audit` accumulate ~MB/year at dojo scale. Not a near-term ceiling. |
| Neon egress | 5 GB/month | Avoid `SELECT *`, missing pagination, and N+1 reads — every byte read out counts. |

Rules of thumb:

- One query per intent, not per row. Use `bun` batch / `IN (...)` / joins; never loop queries in Go.
- Filter, count, and paginate in SQL — not in app memory after a full fetch.
- No goroutine pools, tickers, or long-running workers in the app.
- Connection pool is fixed at 25 open / 10 idle / 5-min lifetime — don't open ad-hoc connections.

> **Deferred — audit-table self-cleanup.** Designed but not built (YAGNI): opportunistic prune of oldest `audit` rows past a configurable threshold (`db.audit_cleanup_max_rows`, default ~50,000), gated cheaply per-write via `pg_class.reltuples` (no seq scan — honors Rule 8), emitting a structured `Warn` log (`event=table_cleanup`, for Cloud Log Explorer) + a `cleanup` audit row. Deferred because `audit` grows ~MB/year at dojo scale and won't cross ~50k rows for years. Revisit when it approaches ~50k rows or traffic scales up. Same pattern fits `sessions` if needed.

## Configuration

Viper merges: env vars (`TENKEI_` prefix) > `config.yaml` > compiled defaults. `config.yaml` is gitignored.

| Variable | Default | Purpose |
| --------- | --------- | --------- |
| `PORT` | `3000` | HTTP listen port |
| `TENKEI_DATABASE_CONNECTION_STRING` | — | PostgreSQL DSN (required) |
| `TENKEI_SERVER_X_CF_BYPASS` | — | Shared header secret |
| `TENKEI_SERVER_MODE` | `production` | `production` → Secure cookies, strict XCFBypass |
| `TENKEI_SERVER_TURNSTILE_SECRET_KEY` | — | Cloudflare Turnstile secret |
| `TENKEI_SERVER_TURNSTILE_ENABLED` | `true` | Toggle Turnstile verification |
| `TENKEI_SERVER_READ_HEADER_TIMEOUT` | `5s` | Prevent Slowloris attacks |
| `TENKEI_SERVER_LOG_LEVEL` | `info` | zerolog global level (debug logs every SQL statement) |
| `TENKEI_SERVER_VERSION` | `0.0.5-YYYYMMDD` | Reported in startup log |

## Local Development

Required env vars (no defaults — the app will not start without them):

- `TENKEI_DATABASE_CONNECTION_STRING` — Postgres DSN (e.g. `postgres://db_user:db_password@127.0.0.1:5451/tenkei?sslmode=disable`).
- `TENKEI_SERVER_X_CF_BYPASS` — shared header secret. If empty, **every** request returns 404 (constant-time compare against an empty key always fails).
- For local login/register testing, set `TENKEI_SERVER_TURNSTILE_ENABLED=false` to skip Cloudflare Turnstile.

```bash
docker compose -f .devcontainer/compose.yml up -d   # start Postgres
make migration_up   # apply migrations (golang-migrate) — REQUIRED before first run
make dev            # go run main.go
```

> **Migrations are manual.** The app never runs them on startup. Skipping them causes 500s on the first DB write — a missing `sessions` table produced a real 500 on login. See `migrations/` and `make migration_up` / `migration_down` / `migration_fix`.

## Release Gates

All must pass before merge. Attach outputs in PR.

```bash
make test          # Race detector + coverage
make lint          # go fmt + staticcheck
golangci-lint run  # If installed
govulncheck ./...  # Vulnerability scan
gosec ./...        # Security scan
make build         # Produces ./tenkei-be-img
```

> **`make test` needs a live DB.** DB-backed tests call `t.Skip` when `TENKEI_DATABASE_CONNECTION_STRING` is unset or unreachable, so `make test` reports a **false green** with near-zero real coverage without it. Always point it at a migrated Postgres before trusting coverage. `make test-short` (`-short`) runs only the non-DB tests.

Known baseline: `gosec` `G117` on `password` fields in JSON structs. Acceptable only when the struct is never logged.

**Commit style**: Conventional Commits (`feat:`, `fix:`, `chore:`, `sec:`).

## Interface Seams (for extension)

- **`Verifier`** — Today `BcryptVerifier`; decorator pattern for 2FA (`requires2FA` seam ready)
- **`SessionStore`** — Today `DBSessionStore`; swap for Redis when scaling. `Validate` returns `(userID, role)` via a sessions⋈users join.
- **`PasswordResetter`** — Defined in `auth/interfaces.go`, not yet implemented. Seam for forgot-password (needs a mailer; none exists). Authenticated change-password is implemented (`POST /v1/auth/password`).
- **`auth.Middleware`** — Shared session + role middleware handle, reused by `/v1/auth` and `/v1/admin` so authn/authz is defined once.

---

**Last Updated**: Aug 2026 | **Maintainer**: Tenkei Dev Team