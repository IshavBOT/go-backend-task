# syntax=docker/dockerfile:1

# ---- Build stage ------------------------------------------------------
FROM golang:1.22-bookworm AS build

# go-sqlite3 uses cgo, so we need gcc + libc headers to build it.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -ldflags="-s -w" -o /out/cli-login-system .

# ---- Runtime stage ------------------------------------------------------
FROM debian:bookworm-slim

# ca-certificates: harmless/standard hygiene even though this binary makes no
# outbound TLS calls today. tzdata: for correct local-time rendering of
# timestamps such as "Registered on" / "Session expires" if TZ is set.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash appuser

WORKDIR /app
COPY --from=build /out/cli-login-system /app/cli-login-system

# The SQLite database lives here; docker-compose.yml mounts a named volume
# on this path so data survives container restarts/recreation.
RUN mkdir -p /data && chown -R appuser:appuser /data /app
VOLUME ["/data"]

ENV DB_PATH=/data/app.db

USER appuser

# This is an interactive CLI, so it must be run with `docker compose run`
# (or `docker run -it`) rather than as a detached background service.
ENTRYPOINT ["/app/cli-login-system"]
