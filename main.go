// Command cli-login-system is a containerized, interactive CLI that
// implements user registration, password + optional TOTP 2FA login, account
// lockout, and session management, backed by SQLite.
package main

import (
	"fmt"
	"os"

	"github.com/osto/cli-login-system/internal/auth"
	"github.com/osto/cli-login-system/internal/cli"
	"github.com/osto/cli-login-system/internal/config"
	"github.com/osto/cli-login-system/internal/db"
	"github.com/osto/cli-login-system/internal/session"
)

func main() {
	cfg := config.Load()

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: could not initialize database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	authSvc := auth.NewService(database, cfg.BcryptCost, cfg.MaxFailedAttempts, cfg.LockoutDuration)
	sessionMgr := session.NewManager(database, cfg.SessionTimeout)

	app, err := cli.New(cfg, authSvc, sessionMgr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: could not start CLI: %v\n", err)
		os.Exit(1)
	}

	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
