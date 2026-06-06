# Tenkei Register Backend

**Repo**: `sapiderman/tenkei-register` | **Language**: Go 1.26 | **License**: Private

## AI Rules

1. Write "Boring Go". Clarity and security over brevity.
2. Use the existing stack (`chi`, `zerolog`, `bun`, `viper`). No new deps without justification.
3. Never log passwords, tokens, WhatsApp numbers, or emergency contacts.
4. Never `panic()` in app code. Return wrapped errors.
5. No global state. Use dependency injection.
6. Write unit tests for all new handlers, middleware, and database functions. Aim for 100% coverage on new code.
7. Read and load the [Kaparthy Guidelines](https://github.com/sapiderman/andrej-karpathy-skills/blob/main/skills/karpathy-guidelines/SKILL.md) before suggesting changes or writing any code. This is your compass for code quality and style.

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
│   ├── auth/                # Login, session, profile
│   ├── register/           # Registration (HTML + JSON dual-format)
│   ├── templates/          # HTML template (register.html)
│   ├── types/              # Shared bun models: User, Audit
│   ├── database/           # DB connection + query logging hook
│   ├── middleware/          # XCFBypass, AccessLog
│   └── server/             # StartServer, ServeWith, response helpers, ErrorResponder
├── migrations/
├── .devcontainer/           # Go + PostgreSQL dev environment
├── Dockerfile               # Multi-stage build (scratch)
└── Makefile
```

## Routes

| Method | Path | Middleware | Purpose |
| ------ | ---- | ---------- | ------- |
| POST | `/v1/register/` | XCFBypass + rate-limit (5/min/IP) + Turnstile | New member registration (HTML form or JSON) |
| GET | `/v1/register/count` | XCFBypass + rate-limit (5/min/IP) | Total registered user count |
| POST | `/v1/auth/login` | XCFBypass + rate-limit (10/min/IP) | Session login (JSON) |
| GET | `/v1/auth/profile` | XCFBypass + session cookie | View profile |
| PUT | `/v1/auth/profile` | XCFBypass + session cookie | Update profile |
| POST | `/v1/auth/logout` | XCFBypass + session cookie | Invalidate session |
| GET | `/health` | None (before XCFBypass) | Liveness probe |

## Middleware Stack (in order)

Applied in `internal/http.go`. Order matters.

1. `RequestID` → 2. `Recoverer` → 3. `AccessLog` → 4. `Heartbeat("/health")` → 5. `XCFBypass` → 6. `Timeout(60s)`

- `/health` bypasses `XCFBypass` (check #4 before #5).
- Auth endpoints additionally use `sessionRequired` middleware (inside `auth.NewRouter`).

## Key Architecture Decisions

- **Dual-format endpoints**: Register routes serve both HTML (via `html/template`) and JSON, selected by `Content-Type` header. The `server.ErrorResponder` interface abstracts this pattern.
- **Anti-enumeration**: Login returns identical `401 "invalid credentials"` for wrong password and nonexistent user.
- **Session cookies**: `HttpOnly`, `Secure` in production, `SameSite=Lax`, scoped to `/v1/auth`.
- **PII masking**: Login failures log `mask(identifier)` only — never raw email/WhatsApp.
- **Connection pool**: 25 max open, 10 idle, 5-minute lifetime.
- **Server timeouts**: Read/Write 10s, Idle 120s, ReadHeaderTimeout from config (default 5s).

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

Known baseline: `gosec` `G117` on `password` fields in JSON structs. Acceptable only when the struct is never logged.

**Commit style**: Conventional Commits (`feat:`, `fix:`, `chore:`, `sec:`).

## Interface Seams (for extension)

- **`Verifier`** — Today `BcryptVerifier`; decorator pattern for 2FA (`requires2FA` seam ready)
- **`SessionStore`** — Today `DBSessionStore`; swap for Redis when scaling
- **`PasswordResetter`** — Defined, not implemented. Seam for forgot-password flow.
- **`ErrorResponder`** — Abstracts HTML vs JSON rendering; implement for new content types.

---

**Last Updated**: Jun 2026 | **Maintainer**: Tenkei Dev Team