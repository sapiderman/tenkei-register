# Tenkei Register – Dev Setup

This repository uses VS Code Dev Containers and Docker Compose to provide a reproducible Go + Postgres development environment.

## Overview

- Go service defined in [main.go](main.go) and supporting packages under [internal/](internal).
- Postgres runs as a sidecar service via [.dev/docker-compose.yml](.dev/docker-compose.yml) during development but may point elsewhere for production.
- Dev Container config is in [.dev/devcontainer.json](.dev/devcontainer.json).

## Prerequisites

- Docker and the Docker Compose plugin
- VS Code with Dev Containers extension; or `devcontainer` CLI

## Quick Start

- VS Code: Open the project and open in container.
- The main app runs on port 8080
- Database can be access on db:5432


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
  - `database.connection_+string` (on the app service): `postgres://db_user:db_password@db:5432/tenkei?sslmode=disable`

Go toolchain: [go.mod](go.mod) declares Go `1.25.5`. The devcontainer image tracks Go 1.x; if you need to pin to exactly 1.25, we can switch to a tagged image.

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

Note: Ensure your server listens (e.g., `http.ListenAndServe(":8080", router)`), then forward 8080 as already configured in the devcontainer.

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

## Troubleshooting

- Healthcheck failure: If the DB healthcheck uses `-U db_user` but `POSTGRES_USER` is `user`, update the healthcheck to `pg_isready -U user -d tenkei` or align the env vars.
- Module download: If `postCreateCommand` didn0t run, manually execute `go mod download` in the Dev Container.
