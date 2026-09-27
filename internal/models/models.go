// Package models defines the domain types shared across the application.
package models

import "time"

// User represents an account stored in the users table.
type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	TOTPSecret     string // empty if 2FA has never been set up
	TOTPEnabled    bool
	FailedAttempts int
	LockedUntil    *time.Time // nil if the account is not currently locked
	CreatedAt      time.Time
	LastLoginAt    *time.Time // nil if the user has never logged in
}

// IsLocked reports whether the account is currently within its lockout window.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

// Session represents an active, authenticated CLI session.
type Session struct {
	ID        string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the session has passed its expiry time.
func (s *Session) IsExpired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}
