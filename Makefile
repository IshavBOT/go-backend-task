.PHONY: build run test docker-build docker-run docker-clean

# Build the binary locally (requires Go 1.22+, and a C compiler for CGO/sqlite3).
build:
	CGO_ENABLED=1 go build -o bin/cli-login-system .

# Run locally against a local SQLite file (bypassing Docker).
run: build
	DB_PATH=./data/app.db ./bin/cli-login-system

# Run the unit test suite.
test:
	CGO_ENABLED=1 go test ./... -v

# Build the Docker image.
docker-build:
	docker compose build

# Run the interactive CLI inside Docker (required for an interactive TTY app).
docker-run:
	docker compose run --rm cli-login-system

# Remove containers, images and the persistent volume (WARNING: deletes all data).
docker-clean:
	docker compose down -v --rmi local
