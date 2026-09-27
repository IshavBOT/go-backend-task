// Package db manages the SQLite connection and schema migrations.
package db

import (
	"database/sql"
	_ "embed" // for go:embed migration file
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3" // sqlite3 driver, registered via side effects
)

// The canonical, human-browsable copy of this schema also lives at
// /migrations/001_init.sql in the repo root for documentation purposes;
// this embedded copy is what actually runs (go:embed cannot reach outside
// the package directory).
//
//go:embed migrations/001_init.sql
var initSchema string

// Open opens (creating if necessary) the SQLite database at path, ensures its
// parent directory exists so it can persist correctly under a Docker volume
// mount, applies the schema migration, and returns a ready-to-use *sql.DB.
func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("creating db directory: %w", err)
		}
	}

	// foreign_keys=on enforces the sessions -> users FK.
	// _busy_timeout avoids "database is locked" errors under light concurrency.
	dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_busy_timeout=5000", path)

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite only supports one writer at a time; a single connection avoids
	// "database is locked" errors that a connection pool would otherwise trigger.
	conn.SetMaxOpenConns(1)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if _, err := conn.Exec(initSchema); err != nil {
		return nil, fmt.Errorf("applying migrations: %w", err)
	}

	return conn, nil
}
