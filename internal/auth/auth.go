// Package auth implements user registration, credential verification,
// password hashing and account lockout logic.
package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/osto/cli-login-system/internal/models"
)

// Sentinel errors returned by this package. Callers (the CLI layer) use
// errors.Is to react appropriately (e.g. show "account locked" vs "bad password").
var (
	ErrUserExists      = errors.New("username already exists")
	ErrInvalidUsername = errors.New("username must be 3-32 characters: letters, numbers, underscore, dot, or dash")
	ErrWeakPassword    = errors.New("password must be at least 8 characters long")
	ErrInvalidCreds    = errors.New("invalid username or password")
	ErrAccountLocked   = errors.New("account is locked due to too many failed attempts")
	ErrUserNotFound    = errors.New("user not found")
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)

// Service provides authentication operations backed by a SQLite database.
type Service struct {
	db                *sql.DB
	bcryptCost        int
	maxFailedAttempts int
	lockoutDuration   time.Duration
}

// NewService constructs an auth Service.
func NewService(db *sql.DB, bcryptCost, maxFailedAttempts int, lockoutDuration time.Duration) *Service {
	return &Service{
		db:                db,
		bcryptCost:        bcryptCost,
		maxFailedAttempts: maxFailedAttempts,
		lockoutDuration:   lockoutDuration,
	}
}

// Register creates a new user account with a securely hashed password.
// It validates the username format and a minimum password strength before
// touching the database.
func (s *Service) Register(username, password string) error {
	if !usernameRe.MatchString(username) {
		return ErrInvalidUsername
	}
	if len(password) < 8 {
		return ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		username, string(hash),
	)
	if err != nil {
		// SQLite raises a UNIQUE constraint error on duplicate usernames.
		if isUniqueConstraintErr(err) {
			return ErrUserExists
		}
		return fmt.Errorf("inserting user: %w", err)
	}
	return nil
}

// VerifyPassword checks a username/password pair, enforcing account lockout.
// It returns the user record on success. On failure it records the failed
// attempt and, once the threshold is crossed, locks the account for
// lockoutDuration.
//
// Note: this does NOT check TOTP. Callers must separately call VerifyTOTP
// for users who have 2FA enabled, as part of the same login attempt.
func (s *Service) VerifyPassword(username, password string) (*models.User, error) {
	user, err := s.GetByUsername(username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Do not reveal whether the username exists.
			return nil, ErrInvalidCreds
		}
		return nil, err
	}

	now := time.Now()
	if user.IsLocked(now) {
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		if lockErr := s.recordFailedAttempt(user, now); lockErr != nil {
			return nil, lockErr
		}
		return nil, ErrInvalidCreds
	}

	if err := s.resetFailedAttempts(user.ID); err != nil {
		return nil, err
	}

	return user, nil
}

// recordFailedAttempt increments the failure counter and locks the account
// if the configured threshold has been reached.
func (s *Service) recordFailedAttempt(user *models.User, now time.Time) error {
	attempts := user.FailedAttempts + 1

	if attempts >= s.maxFailedAttempts {
		lockedUntil := now.Add(s.lockoutDuration)
		_, err := s.db.Exec(
			`UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`,
			attempts, lockedUntil, user.ID,
		)
		return err
	}

	_, err := s.db.Exec(
		`UPDATE users SET failed_attempts = ? WHERE id = ?`,
		attempts, user.ID,
	)
	return err
}

// resetFailedAttempts clears the failure counter and any lockout after a
// successful login.
func (s *Service) resetFailedAttempts(userID int64) error {
	_, err := s.db.Exec(
		`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?`,
		userID,
	)
	return err
}

// RemainingLockout returns how much time is left on a user's lockout, or
// zero if the account is not currently locked.
func RemainingLockout(user *models.User) time.Duration {
	if user.LockedUntil == nil {
		return 0
	}
	d := time.Until(*user.LockedUntil)
	if d < 0 {
		return 0
	}
	return d
}

// TouchLastLogin stamps the user's last_login_at with the current time.
// Called after a fully successful login (password + TOTP if enabled).
func (s *Service) TouchLastLogin(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now(), userID)
	return err
}

// GetByUsername looks up a user by username.
func (s *Service) GetByUsername(username string) (*models.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, totp_secret, totp_enabled,
		        failed_attempts, locked_until, created_at, last_login_at
		 FROM users WHERE username = ?`,
		username,
	)
	return scanUser(row)
}

// GetByID looks up a user by primary key.
func (s *Service) GetByID(id int64) (*models.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, totp_secret, totp_enabled,
		        failed_attempts, locked_until, created_at, last_login_at
		 FROM users WHERE id = ?`,
		id,
	)
	return scanUser(row)
}

// SetTOTPSecret persists a (not-yet-confirmed or confirmed) TOTP secret and
// enabled flag for a user.
func (s *Service) SetTOTPSecret(userID int64, secret string, enabled bool) error {
	_, err := s.db.Exec(
		`UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`,
		secret, enabled, userID,
	)
	return err
}

// DisableTOTP clears a user's 2FA configuration entirely.
func (s *Service) DisableTOTP(userID int64) error {
	_, err := s.db.Exec(
		`UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?`,
		userID,
	)
	return err
}

func scanUser(row *sql.Row) (*models.User, error) {
	var u models.User
	var totpSecret sql.NullString
	var lockedUntil sql.NullTime
	var lastLoginAt sql.NullTime

	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &totpSecret, &u.TOTPEnabled,
		&u.FailedAttempts, &lockedUntil, &u.CreatedAt, &lastLoginAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanning user: %w", err)
	}

	u.TOTPSecret = totpSecret.String
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		u.LastLoginAt = &lastLoginAt.Time
	}
	return &u, nil
}

// isUniqueConstraintErr detects SQLite's UNIQUE constraint violation without
// importing the sqlite3 driver's error type directly, keeping this file
// driver-agnostic-ish and simple to read.
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return regexp.MustCompile(`UNIQUE constraint failed`).MatchString(msg)
}
