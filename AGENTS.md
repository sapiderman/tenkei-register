# Tenkei Register Backend

## Overview

Backend service for **Tenkei Aikidojo** registration and member management. Written in Go, prioritizing simplicity, security, and maintainability.

**Repo**: `sapiderman/tenkei-register`
**Language**: Go 1.26
**License**: Private / Proprietary

> NOTE: This repository includes a generated graph output directory at `graphify-out/`. AI models should inspect `graphify-out/` first for structured project context before scanning raw source files.

## AI Rules

**Guidelines for Gemini/Agents:**

1.  **Idiomatic**: Write "Boring Go" (1.26 style). Prefer clarity and security over brevity.
2.  **Libraries**: Use the established stack (`chi`, `zerolog`, `bun`, `viper`). Do not introduce new external dependencies unless absolutely necessary.
3.  **Security**: Treat all input as hostile. Validate early. Never log secrets or PII (like WhatsApp numbers).
4.  **No Panics**: Never use `panic()` in application code. Return errors wrapped with context.
5.  **Critique**: Before writing code, list 3 risks for non-trivial changes.
6.  **Clean Code**: Ensure no unused variables, functions, or imports are left behind. Fix all `staticcheck` and `go fmt` warnings before completing a task.

## Tech Stack

### Core

-   **Go**: 1.26 (Strict Mode).
-   **Router**: `github.com/go-chi/chi/v5`.
-   **Database**: PostgreSQL (via `github.com/uptrace/bun` and `pgdriver`).
-   **Validation**: `github.com/go-playground/validator/v10`.
-   **Security**: `golang.org/x/crypto/bcrypt` (Password Hashing).
-   **Logging**: `github.com/rs/zerolog` (Structured).
-   **Config**: `github.com/spf13/viper` (Environment Variables & YAML).

### Tools

-   **Linting**: `golangci-lint` (Latest).
-   **Build**: `Makefile`.
-   **Docker**: Multi-stage builds (Distroless final image).
-   **Migrate**: Native SQL execution or external tools.

## Configuration

Viper merges configuration from multiple sources in this priority order (highest wins):

1. **Environment variables** (prefixed `TENKEI_`, e.g., `TENKEI_DATABASE_CONNECTION_STRING`).
2. **`config.yaml`** in the project root (local development only).
3. **Compiled defaults** in `config/config.go`.

> **Security**: `config.yaml` is in `.gitignore` and must never be committed. It typically contains local secrets. Use `config.example.yaml` as a template.

### Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | No | `3000` | HTTP listen port (Cloud Run compatible). |
| `TENKEI_DATABASE_CONNECTION_STRING` | Yes | none | PostgreSQL DSN used by Bun/pgdriver. |
| `TENKEI_SERVER_TURNSTILE_SECRET_KEY` | Yes (when Turnstile enabled) | none | Cloudflare Turnstile secret key. |
| `TENKEI_SERVER_TURNSTILE_ENABLED` | No | `true` | Enable/disable Turnstile server-side verification. |
| `TENKEI_SERVER_X_CF_BYPASS` | Yes (prod) | none | Shared header secret checked by `XCFBypass` middleware. |
| `TENKEI_SERVER_MODE` | No | `production` | Runtime mode indicator for environment-specific behavior. |

## Structure

```text
tenkei-register/
├── main.go              # Main entry point
├── config/              # Configuration management
├── internal/            # Private application code
│   ├── database/        # Database connection and hooks
│   ├── middleware/      # HTTP middlewares (e.g., XCFBypass, AccessLog)
│   ├── register/        # Registration domain (handlers, models, db)
│   ├── server/          # Server utilities and response helpers
│   └── templates/       # HTML templates
├── migrations/          # SQL migration files
├── go.mod               # Dependencies
└── Makefile             # Build commands
```

## Standards

### Coding

* **Errors**: Wrap errors with `fmt.Errorf("...: %w", err)`. Use `errors.Is` / `errors.As`.
* **Iterators**: Use standard `for range` loops over custom iterator functions where applicable (Go 1.23+ pattern).
* **Concurrency**: Use `errgroup` for synchronization. Context propagation is mandatory.
* **Interfaces**: Define interfaces where *used* (Consumer), not where defined.

### Security

* **SQL**: Use `bun` ORM for parameterized queries to prevent SQL injection.
* **Auth**: Cloudflare Turnstile for bot protection.
* **Access Control**: All endpoints are protected by the `XCFBypass` middleware, requiring `x-cf-bypass`.
* **XCFBypass Policy**:
	* **Production**: `x-cf-bypass` is required and invalid/missing values should be masked as `404`.
	* **Non-Production**: Allow explicit documented bypass strategy per environment (never by ad-hoc code edits).
* **Request Limits**: Cap JSON request bodies with `http.MaxBytesReader` (1 MiB default on registration endpoint).
* **Turnstile IP**: Prefer trusted `CF-Connecting-IP`; fallback to `RemoteAddr`.
* **Logging**: Never log passwords, token values, or direct contact identifiers (WhatsApp/emergency numbers).
* **Sanitization**: Escape HTML inputs when rendering templates, validate JSON payloads strictly.

### Logging Privacy Rules

Never log these fields, even in debug mode:

* `password`
* `password_confirm`
* `cf_turnstile_response`
* `whatsapp`
* `emergency_contact_number`

### Middleware Stack Order

Chi middleware is applied in order. The current stack (defined in `internal/http.go`):

1. `middleware.RequestID` — Assigns a unique request ID.
2. `middleware.RealIP` — Extracts real client IP from proxy headers.
3. `middleware.Recoverer` — Catches panics and returns 500.
4. `mymiddleware.AccessLog` — Structured request/response logging.
5. `middleware.Heartbeat("/health")` — Returns 200 on `/health` (bypasses later middleware).
6. `mymiddleware.XCFBypass` — Rejects requests without valid `x-cf-bypass` header (returns masked 404).
7. `middleware.Timeout(60s)` — Cancels request context after 60 seconds.

> **Important**: `Heartbeat` must come before `XCFBypass` so `/health` is accessible without the bypass header.

### Anti-Patterns

* **Global State**: No global variables (e.g., `var DB *sql.DB`). Use Dependency Injection.
* **"Magic"**: Avoid reflection. Be explicit.

## Database Schema

Migrations are in `migrations/`. Current schema (`000001_create_tables.up.sql`):

### `users` Table

| Column | Type | Constraints |
|---|---|---|
| `id` | int4 | PK, auto-increment |
| `created_at` | timestamptz | DEFAULT CURRENT_TIMESTAMP |
| `updated_at` | timestamptz | DEFAULT CURRENT_TIMESTAMP |
| `email` | varchar | UNIQUE INDEX |
| `name` | varchar | — |
| `whatsapp_number` | varchar | NOT NULL, UNIQUE INDEX |
| `password_hash` | varchar | NOT NULL |
| `join_date` | timestamptz | NOT NULL, DEFAULT CURRENT_TIMESTAMP, INDEX |
| `dojo` | varchar | — |
| `date_of_birth` | date | — |
| `rank` | varchar | — |
| `last_grading_date` | date | — |
| `role` | varchar | DEFAULT 'user' |
| `consent_datastore` | boolean | DEFAULT false |
| `consent_marketing` | boolean | DEFAULT false |
| `medical_conditions` | text | — |
| `emergency_contact_name` | varchar | — |
| `emergency_contact_number` | varchar | — |

### `audit` Table

| Column | Type | Constraints |
|---|---|---|
| `id` | int4 | PK, auto-increment |
| `created_at` | timestamptz | DEFAULT CURRENT_TIMESTAMP |
| `updated_at` | timestamptz | DEFAULT CURRENT_TIMESTAMP |
| `user_id` | int4 | INDEX |
| `action` | varchar | — |

## Local Development Quickstart

```bash
# 1. Clone
git clone git@github.com:sapiderman/tenkei-register.git
cd tenkei-register

# 2. Configure
cp config.example.yaml config.yaml
# Edit config.yaml with your local PostgreSQL DSN and test Turnstile key

# 3. Database
# Start PostgreSQL (e.g., via Docker) and run migrations:
psql $YOUR_DSN -f migrations/000001_create_tables.up.sql

# 4. Run
go run main.go
# Server listens on the port configured in config.yaml (default: 3000)
```

## Workflow & Release Gates

All of the following must pass before merge/release. Attach command outputs in the PR:

| Step | Command | Notes |
|---|---|---|
| Test | `make test` | Runs tests with race detector and coverage. Must pass. |
| Lint | `make lint` | Runs `go fmt` and `staticcheck`. Must pass. |
| Advanced Lint | `golangci-lint run` | Must pass (if installed). |
| Vulnerabilities | `govulncheck -show verbose ./...` | Must pass. |
| Security | `gosec ./...` | Must pass. |
| Build | `make build` | Produces `./tenkei-be-img`. |
| Run | `make run` or `./tenkei-be-img` | — |

* Findings from `staticcheck` and `gosec` are release blockers unless explicitly accepted with rationale.
* If suppressing a finding (e.g., false positive), document the reason inline and in PR notes.
* Any exception requires explicit maintainer approval with a written risk acceptance note.

### Known Baseline Findings

* `gosec` may report `G117` on JSON payload field names like `password`.
* This is acceptable only when the payload struct is never logged and values are handled transiently.
* If suppressed, require inline rationale and reviewer acknowledgement in PR.

**Commit Style**: Conventional Commits (`feat:`, `fix:`, `chore:`, `sec:`).

## Domain

### Context

* **Dojo**: Tenkei Aikidojo (Jakarta).
* **Role**: Registration System.
* **Users**: Admin (Sensei/Staff) vs. Member (Student).
* **Data**: PII (Names, Phones, Emails) must always be protected.

## API & Data

### Protocol

* **Format**: JSON (`Content-Type: application/json`) and HTML Form submissions.
* **Response**: Flat JSON structure (e.g., `{"status": "ok"}` or `{"error": "message"}`) or HTML template rendering.

### Response Contract

JSON API response conventions:

* **201 Created**: `{"status":"ok"}`
* **400 Bad Request**: `{"error":"validation or security verification failed"}`
* **404 Not Found**: `{"message":"Not Found"}` (used for access masking by `XCFBypass`)
* **409 Conflict**: `{"error":"An account with this email or WhatsApp number already exists."}`
* **500 Internal Server Error**: `{"error":"internal server error"}`

### Validation

* **Library**: `go-playground/validator` (v10) and explicit struct checks.
* **Logic**: Validate at the *Handler* level before database insertion.

## Deploy

* **Target**: Linux Container (Docker).
* **Platform**: `tenkei-be-img` (Go binary).
* **Health**: Expose `/health` endpoint via `chi` middleware.

## Emergency

### Contacts

* **Lead Dev**: sapiderman
* **Infra**: `tenkei-backend` Status Page.

### Recovery

* **Panic**: Application auto-restarts (Docker). Check logs for stack trace.
* **DB Down**: Service returns 503 Service Unavailable.

---

**Last Updated**: Feb 2026
**Maintainer**: Tenkei Dev Team
