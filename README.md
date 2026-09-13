# Tenkei Backend

This repository handles back end services.

## Development Overview

- The stack is based on Golang 1.26.x
- Data is stored in a Postgres database.
- Routes are handled using chi router.

## Quick Start

- VSCode: Open the project and open in container.
- Create a local config.yaml in the root with your preferred configurations such as ports etc.
- The main app runs on port 3000.
- Database can be access on db:5432 from the container.

The Dev Container mounts the workspace at `/workspace` and runs `go mod download` on first create.

## Services & Ports

- App container: Microsoft Go devcontainer image (`go:1-ubuntu-24.04`)
- Database: Postgres 18 service defined in compose
- Forwarded ports:
  - 5451:5432 → Postgres
  - 3001:3000 → App server

## Configuration

- Compose environment in [.devcontainer/compose.yml](.devcontainer/compose.yml):
  - `POSTGRES_USER`: `db_user`
  - `POSTGRES_PASSWORD`: `db_password`
  - `POSTGRES_DB`: `tenkei`
- Config.yaml.config:
  - `database.connection_string` (on the app service): `postgres://db_user:db_password@db:5432/tenkei?sslmode=disable`

Go toolchain: [go.mod](go.mod) declares Go `1.26.6`. The devcontainer image tracks Go 1.x; if you need to pin to exactly 1.26.6, we can switch to a tagged image.

## Common Commands

Start/refresh the database:

```bash
docker compose -f .devcontainer/compose.yml pull db
docker compose -f .devcontainer/compose.yml up -d db
```

Stop the database:

```bash
docker compose -f .devcontainer/compose.yml down
```

Run the application inside the Dev Container:

```bash
# in the Dev Container terminal
go run ./...
```

Note: Ensure your server listens (e.g., `http.ListenAndServe(":3000", router)`), then forward 3000 as already configured in the devcontainer.

## Database Access

Connect to Postgres from the host (Linux/macOS):

```bash
psql "postgres://db_user:db_password@localhost:5451/tenkei?sslmode=disable"
```

Or from the container:

```bash
docker exec -it dev-db-1 psql -U db_user -d tenkei

or

psql "postgres://db_user:db_password@db:5432/tenkei?sslmode=disable"
```

## Two-Factor Auth (TOTP, optional)

Members can protect their account with an authenticator app (Google/Microsoft
Authenticator, Aegis, 1Password — any RFC 6238 TOTP app). All endpoints are
JSON under `/v1/auth` and need the session cookie. They return **404** unless
`TENKEI_TOTP_ENABLED=true`.

Enrollment (authenticated member):

1. `POST /v1/auth/2fa/enroll` — body `{}` → `200 {"secret":"<base32>","otpauth_url":"otpauth://totp/..."}`.
   Render `otpauth_url` as a QR code. The secret is shown **once**, never again.
2. `POST /v1/auth/2fa/confirm` — body `{"code":"123456","current_password":"..."}` → `200 {"status":"ok"}`.
   Arms 2FA for the account. Wrong password → `403`; wrong code → `400`.

Login for an enrolled member (second step):

1. `POST /v1/auth/login` → `200 {"status":"2fa_required"}` (session cookie is pending, 5-minute TTL).
2. `POST /v1/auth/2fa/verify` — body `{"code":"123456"}` → `200 {"status":"ok"}`.
   Wrong code → `401 {"error":"invalid code"}`; 5 wrong codes → `401 {"error":"too many attempts, login again"}`
   and the pending session is deleted (fresh login required).

Disabling:

1. `POST /v1/auth/2fa/disable` — body `{"code":"123456","current_password":"..."}` → `200 {"status":"ok"}`.

Other codes: enroll while already enabled → `409`; disable while not enabled → `400`;
confirm without a pending enrollment → `400`.
