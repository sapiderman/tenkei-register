# Build stage
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
# CGO_ENABLED=0 is required for a static binary that can run in scratch/alpine
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Run stage
FROM alpine:latest
ENV USER=appuser UID=1000 PATH=/app:${PATH} LISTEN_ADDR=:3000

WORKDIR /app

# Copy the Pre-built binary from the previous stage
COPY --from=builder /app/main .

# Copy necessary static files and config
COPY --from=builder /app/internal/templates ./internal/templates
COPY --from=builder /app/migrations ./migrations

# add non-root user and switch to it
RUN apk --no-cache add curl
RUN adduser -D -g "" -h "/nonexistent" -s "/sbin/nologin" -H -u "${UID}" "${USER}"
RUN chown ${USER}:${USER} /app/main
USER ${USER}:${USER}

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]
