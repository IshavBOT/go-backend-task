# Containerized CLI Login System with Optional 2FA

A secure, interactive command-line authentication system written in Go. It
supports user registration, username/password login, optional TOTP-based
two-factor authentication (Google Authenticator compatible), account
lockout after repeated failed attempts, and session management with a
configurable timeout — all backed by a persistent SQLite database and
packaged to run in Docker.

## Features

- **Registration & login** with bcrypt-hashed passwords (never stored or
  logged in plaintext).
- **Optional TOTP 2FA** — `enable-2fa` shows a secret + `otpauth://`
  provisioning URI you can scan into Google Authenticator, Authy, etc.
- **Account lockout** after a configurable number of consecutive failed
  login attempts, with an automatic, configurable cool-down period.
- **Session management** — sessions expire after a configurable idle
  timeout and are refreshed on activity (sliding window).
- **Interactive CLI** with command history (↑ / ↓) and tab-completion,
  built on `chzyer/readline`.
- **Persistent SQLite storage**, mounted as a Docker volume so data
  survives container restarts and rebuilds.
- **Unit tests** for the auth, session, and TOTP packages (20 tests).

## Project Structure

```
.
├── main.go                     # Entry point: wires config, db, auth, session, CLI together
├── internal/
│   ├── config/                 # Environment-variable based configuration
│   ├── db/                     # SQLite connection + embedded schema migration
│   │   └── migrations/001_init.sql
│   ├── models/                 # User / Session domain types
│   ├── auth/                   # Registration, password verification, lockout logic (+tests)
│   ├── totp/                   # TOTP secret generation & validation (+tests)
│   ├── session/                # Session create/validate/refresh/destroy (+tests)
│   └── cli/                    # Interactive REPL: commands, prompts, help text
├── migrations/001_init.sql     # Human-readable copy of the schema (see note below)
├── Dockerfile                  # Multi-stage build (compiles with CGO for go-sqlite3)
├── docker-compose.yml          # Runs the app with a persistent named volume
├── Makefile                    # Convenience targets (build/run/test/docker-*)
└── go.mod / go.sum
```

> **Note on the schema file:** `migrations/001_init.sql` at the repo root is
> the canonical, browsable copy of the schema for documentation purposes.
> The binary actually embeds `internal/db/migrations/001_init.sql` (an
> identical copy) via `go:embed`, because Go's embed directive cannot reach
> outside a package's own directory. Both files are kept in sync; if you
> ever change the schema, update both.

## How It Works

### Database
A single SQLite file (`/data/app.db` inside the container) holds two tables:

- `users` — username, bcrypt password hash, TOTP secret + enabled flag,
  failed-attempt counter, lockout expiry, created-at, last-login-at.
- `sessions` — session token (UUID), owning user, created-at, expires-at.

The schema is applied automatically and idempotently (`CREATE TABLE IF NOT
EXISTS`) every time the app starts, so no separate migration step is
required.

### Account lockout
Each failed login increments `failed_attempts`. Once it reaches
`MAX_FAILED_ATTEMPTS`, the account is locked until `locked_until`, computed
as `now + LOCKOUT_DURATION`. A successful login resets the counter and
clears the lockout.

### Sessions
On successful login (password, and TOTP code if 2FA is enabled), a new
session row is created with `expires_at = now + SESSION_TIMEOUT`. Any prior
session for that user is deleted, so a user has at most one active session
at a time. Every command issued while logged in refreshes (slides forward)
the session's expiry. If a session has expired, the CLI detects this before
showing the next prompt and returns you to the logged-out state.

### 2FA (TOTP)
`enable-2fa` generates a new random secret and shows it as both a base32
string (for manual entry) and a full `otpauth://` URI (which any
authenticator app can import, e.g. by generating a QR code from it, or via
apps that accept a URI directly). You must confirm setup by entering a
current 6-digit code before it's actually turned on, which prevents you
from locking yourself out with a typo'd or incompatible secret. Once
enabled, `login` will always ask for a 2FA code after the password. Codes
are validated with a ±1 time-step allowance (±30s) to tolerate minor clock
drift, per standard TOTP practice.

## Requirements

- Docker and Docker Compose (recommended way to run this), **or**
- Go 1.22+ and a C compiler (gcc) if you want to build/run natively,
  since the SQLite driver (`mattn/go-sqlite3`) uses CGO.

## Setup & Running (Docker — recommended)

This is an **interactive** program, so it must be run with an attached
terminal (`docker compose run`), not `docker compose up` (which would start
it detached with no console attached).

```bash
# Build the image
docker compose build

# Run it interactively
docker compose run --rm cli-login-system
```

Data is stored in the named volume `db-data`, defined in
`docker-compose.yml`, so it survives `docker compose run` being invoked
again, container recreation, and image rebuilds. To wipe all data and start
fresh:

```bash
docker compose down -v
```

### Configuration (environment variables)

All of these are set with sensible defaults in `docker-compose.yml` and can
be overridden there or via the shell:

| Variable               | Default              | Description                                             |
|-------------------------|---------------------|----------------------------------------------------------|
| `DB_PATH`               | `/data/app.db`      | Path to the SQLite database file                          |
| `SESSION_TIMEOUT`       | `15m`               | Idle session timeout (Go duration, e.g. `30s`, `15m`, `2h`) |
| `MAX_FAILED_ATTEMPTS`   | `5`                 | Failed logins allowed before lockout                       |
| `LOCKOUT_DURATION`      | `5m`                | How long an account stays locked after lockout             |
| `BCRYPT_COST`           | `12`                | bcrypt work factor (higher = slower/more secure)           |
| `TOTP_ISSUER`           | `CLI-Login-System`  | Issuer name shown in authenticator apps                    |

Example — run with a 30-second session timeout and stricter lockout:

```bash
docker compose run --rm \
  -e SESSION_TIMEOUT=30s \
  -e MAX_FAILED_ATTEMPTS=3 \
  cli-login-system
```

## Setup & Running (natively, without Docker)

```bash
# Install dependencies and build
go build -o bin/cli-login-system .

# Run (SQLite file will be created at ./data/app.db)
DB_PATH=./data/app.db ./bin/cli-login-system
```

Or simply:

```bash
make build
make run
```

## Usage Guide

On startup you'll see a banner and a `>` prompt. Use ↑ / ↓ for command
history and Tab for command completion.

### Before logging in

| Command    | Description                                      |
|------------|---------------------------------------------------|
| `register` | Create a new account (prompts for username/password, with confirmation) |
| `login`    | Log in with username/password (+ TOTP code if 2FA is enabled) |
| `help`     | List available commands                           |
| `exit`     | Quit the program                                   |

### After logging in

| Command       | Description                                            |
|---------------|----------------------------------------------------------|
| `whoami`      | Show your account details (see below)                    |
| `enable-2fa`  | Set up TOTP 2FA (shows secret + QR-ready URI, requires confirmation code) |
| `disable-2fa` | Turn off 2FA                                              |
| `logout`      | End your session                                          |
| `help`        | List available commands                                   |
| `exit`        | Quit the program                                           |

### Example session

```
=================================================
 Containerized CLI Login System  (type 'help')
=================================================
> register
Username: alice
Password: ********
Confirm password: ********
Account "alice" created successfully. You can now 'login'.
> login
Username: alice
Password: ********

Welcome, alice!
------------------------------------------------
  Username:          alice
  Registered on:     Sun, 27 Sep 2026 16:42:52 UTC
  MFA status:        disabled
  Session expires:   Sun, 27 Sep 2026 16:57:52 UTC
  Last login:        (this is your first login)
------------------------------------------------
(alice)> enable-2fa

Scan this in Google Authenticator (or any TOTP app), or enter the secret manually:
  Secret:           ORJ3S3EBCJ7WWYRVC3HYE7RXY3SDLYSF
  Provisioning URI: otpauth://totp/CLI-Login-System:alice?...

To confirm setup, enter the 6-digit code from your app now.
2FA code: 734560
Two-factor authentication is now enabled on your account.
(alice)> logout
Goodbye, alice. You have been logged out.
> exit
Goodbye!
```

After enabling 2FA, subsequent `login` attempts for that user will prompt
for a `2FA code:` right after the password.

### Auto-displayed user details

After every successful login, and whenever you run `whoami`, the CLI shows:

- Username
- Registration date
- MFA status (enabled/disabled)
- Session expiration time
- Last login time (or a note that this is your first login)

## Testing

Unit tests cover the core security-relevant logic: registration validation,
password verification, account lockout timing, TOTP secret generation and
validation, and full session lifecycle (create/validate/expire/refresh/destroy).

```bash
go test ./... -v
# or
make test
```

All 20 tests pass, and `go vet ./...` is clean.

## Security Notes

- Passwords are hashed with **bcrypt** (configurable cost factor, default
  12) — never stored or transmitted in plaintext, and never echoed to the
  terminal when typed (masked input via the readline library).
- Login failure messages are intentionally generic ("invalid username or
  password") to avoid revealing whether a username exists.
- TOTP secrets are only shown once, at generation time, and setup requires
  confirming a live code before being persisted as "enabled."
- Sessions are single-use per account (creating a new session invalidates
  any previous one) and expire server-side based on `expires_at`, not
  merely on client trust.
- SQLite is used with a single-connection pool and `_busy_timeout` to avoid
  corruption/locking issues, appropriate for a single-process CLI tool.

## A note on dependency fetching in restricted network environments

This project's `go.mod` includes three `replace` directives:

```
replace golang.org/x/sys => github.com/golang/sys v0.29.0
replace golang.org/x/crypto => github.com/golang/crypto v0.31.0
replace golang.org/x/term => github.com/golang/term v0.27.0
```

These exist because this project was developed in a sandboxed environment
whose network egress allowlist included `github.com` but not
`proxy.golang.org` or `golang.org` (the usual sources Go uses to resolve
`golang.org/x/...` packages). The replace directives point Go at the
identical upstream code mirrored on GitHub instead. This has no effect on
correctness or security — it's purely about where the source is fetched
from — and everything builds and runs identically with or without normal
internet access. If you build this on a machine with unrestricted internet
access, you're welcome to remove these three lines and run `go mod tidy`;
it will resolve the same versions through the standard Go module proxy.

## Deliverables Checklist

- [x] Source code, organized into clear packages with comments
- [x] `Dockerfile` + `docker-compose.yml`
- [x] `README.md` (this file) with setup + usage instructions
- [x] Database schema/migration included (`migrations/001_init.sql`)
- [x] Unit tests for core functionality (`internal/auth`, `internal/session`, `internal/totp`)
