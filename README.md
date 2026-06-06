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
  - 5432 → Postgres
  - 8080 → Reserved for app server (if/when you listen on it)

## Configuration

- Compose environment in [.dev/docker-compose.yml](.dev/docker-compose.yml):
  - `POSTGRES_USER`: `db_user`
  - `POSTGRES_PASSWORD`: `db_password`
  - `POSTGRES_DB`: `tenkei`
- Config.yaml.config:
  - `database.connection_string` (on the app service): `postgres://db_user:db_password@db:5432/tenkei?sslmode=disable`

Go toolchain: [go.mod](go.mod) declares Go `1.26.3`. The devcontainer image tracks Go 1.x; if you need to pin to exactly 1.26, we can switch to a tagged image.

## Common Commands

Start/refresh the database:

```bash
docker compose -f .devcontainer/docker-compose.yml pull db
docker compose -f .devcontainer/docker-compose.yml up -d db
```

Stop the database:

```bash
docker compose -f .devcontainer/docker-compose.yml down
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
psql "postgres://db_user:db_password@localhost:5437/tenkei?sslmode=disable"
```

Or from the container:

```bash
docker exec -it dev-db-1 psql -U db_user -d tenkei

or

psql "postgres://db_user:db_password@db:5432/tenkei?sslmode=disable"
```
