# backend makefile

CURRENT_PATH ?= $(shell pwd)
IMAGE_NAME ?= tenkei-be-img
DATABASE_URL ?= postgres://db_user:db_password@localhost:5437/tenkei?sslmode=disable

.PHONY: all test clean build docker

dev_deps:
	docker compose -f .devcontainer/docker-compose.yml up -d

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

run: build
	go run main.go

test-coverage: test
	go tool cover -html=coverage.out

docker:
	docker build -t $(IMAGE_NAME) -f ./Dockerfile .

docker-run:
	docker run -p 3000:3000 -d $(IMAGE_NAME)