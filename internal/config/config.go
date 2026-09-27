// Package config centralizes application configuration.
// All values can be overridden via environment variables, which makes the
// system easy to tune from docker-compose.yml without touching code.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds every tunable knob for the login system.
type Config struct {
	// DBPath is the filesystem path to the SQLite database file.
	DBPath string

	// SessionTimeout controls how long an authenticated session stays valid
	// after login (or after being refreshed), if the user does not explicitly log out.
	SessionTimeout time.Duration

	// MaxFailedAttempts is the number of consecutive failed login attempts
	// allowed before an account is locked out.
	MaxFailedAttempts int

	// LockoutDuration is how long an account stays locked after hitting
	// MaxFailedAttempts.
	LockoutDuration time.Duration

	// BcryptCost controls the bcrypt work factor used to hash passwords.
	BcryptCost int

	// TOTPIssuer is the "issuer" name shown in Google Authenticator / Authy
	// when a user scans the QR code / enters the secret.
	TOTPIssuer string
}

// Load reads configuration from environment variables, falling back to
// sensible defaults for anything not set. This is the single source of
// truth for configuration in the whole application.
func Load() *Config {
	return &Config{
		DBPath:            getEnv("DB_PATH", "/data/app.db"),
		SessionTimeout:    getEnvDuration("SESSION_TIMEOUT", 15*time.Minute),
		MaxFailedAttempts: getEnvInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:   getEnvDuration("LOCKOUT_DURATION", 5*time.Minute),
		BcryptCost:        getEnvInt("BCRYPT_COST", 12),
		TOTPIssuer:        getEnv("TOTP_ISSUER", "CLI-Login-System"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		// Accept either a Go duration string ("15m", "30s") or a plain
		// integer number of seconds for convenience in docker-compose.yml.
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return fallback
}
