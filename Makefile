# backend makefile

CURRENT_PATH ?= $(shell pwd)
IMAGE_NAME ?= tenkei-be-img
DATABASE_URL ?= postgres://db_user:db_password@127.0.0.1:5451/tenkei?sslmode=disable

# Scratch-database test run (see test-db below): parameters for the running
# postgres container and the throwaway test database it creates/drops.
PG_CONTAINER ?= tenkei-postgres
PG_USER ?= db_user
PG_PASSWORD ?= db_password
PG_PORT ?= 5452
TEST_DB ?= tenkei_test

.PHONY: all test test-db clean build docker

dev_deps:
	docker compose -f .devcontainer/compose.yml up -d

migration_up:
	migrate -path migrations -database "$(DATABASE_URL)" -verbose up

migration_down:
	migrate -path migrations -database "$(DATABASE_URL)" -verbose down

migration_fix:
	migrate -path migrations -database "$(DATABASE_URL)" force VERSION

dev:
	go run main.go

build: lint
	#go build -a -o $(IMAGE_NAME) main.go
	go build -buildvcs=false -a -ldflags '-extldflags "-static"' -o $(IMAGE_NAME) main.go

clean:
	go clean
	rm -f $(IMAGE_NAME)

lint:
	go fmt ./...
	GOFLAGS=-buildvcs=false staticcheck ./...

test-short: lint
	go test ./... -v -covermode=count -coverprofile=coverage.out -short

proto: lint
	protoc --go_out=. --go_opt=paths=source_relative ./internal/proto/user.proto

test: lint
	go test ./... -v -race -covermode=atomic -coverprofile=coverage.out

# test-db runs the suite against a throwaway database instead of the dev
# database: it creates $(TEST_DB), applies migrations/*.up.sql, runs go test,
# and always drops the scratch DB. Some tests (last-superuser guard) require
# a database with no pre-existing superusers, so the dev DB is unsuitable.
test-db:
	@bash -c '\
	docker exec $(PG_CONTAINER) psql -U $(PG_USER) -d postgres -c "DROP DATABASE IF EXISTS $(TEST_DB)" && \
	docker exec $(PG_CONTAINER) psql -U $(PG_USER) -d postgres -c "CREATE DATABASE $(TEST_DB) OWNER $(PG_USER)" && \
	for f in ./migrations/*.up.sql; do \
	  docker exec -i $(PG_CONTAINER) psql -U $(PG_USER) -d $(TEST_DB) -v ON_ERROR_STOP=1 -q < $$f || exit 1; \
	done; \
	TENKEI_DATABASE_CONNECTION_STRING="postgres://$(PG_USER):$(PG_PASSWORD)@127.0.0.1:$(PG_PORT)/$(TEST_DB)?sslmode=disable" go test ./... -race -covermode=atomic -coverprofile=coverage.out; \
	status=$$?; \
	docker exec $(PG_CONTAINER) psql -U $(PG_USER) -d postgres -c "DROP DATABASE IF EXISTS $(TEST_DB)" >/dev/null 2>&1; \
	exit $$status'

run: build
	go run main.go

test-coverage: test
	go tool cover -html=coverage.out

docker:
	docker build -t $(IMAGE_NAME) -f ./Dockerfile .

docker-run:
	docker run -p 3000:3000 -d $(IMAGE_NAME)