// Package session manages authenticated CLI sessions, persisted in SQLite so
// that timeout enforcement survives process restarts and is trivially
// auditable via the database.
package session

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/osto/cli-login-system/internal/models"
)

// ErrSessionExpired is returned by Validate when a session token exists but
// has passed its expiry time.
var ErrSessionExpired = errors.New("session has expired")

// ErrSessionNotFound is returned by Validate when the token does not exist,
// e.g. it was never issued or was already destroyed by Logout.
var ErrSessionNotFound = errors.New("session not found")

// Manager creates and validates sessions with a fixed configured timeout.
type Manager struct {
	db      *sql.DB
	timeout time.Duration
}

// NewManager constructs a session Manager. timeout is how long a session
// remains valid from the moment it is created (or refreshed).
func NewManager(db *sql.DB, timeout time.Duration) *Manager {
	return &Manager{db: db, timeout: timeout}
}

// Create starts a new session for userID and returns it. Any prior sessions
// for the same user are removed first, so a user has at most one active
// session at a time (simple and predictable for a CLI tool).
func (m *Manager) Create(userID int64) (*models.Session, error) {
	if _, err := m.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return nil, fmt.Errorf("clearing old sessions: %w", err)
	}

	now := time.Now()
	sess := &models.Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.timeout),
	}

	_, err := m.db.Exec(
		`INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.CreatedAt, sess.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	return sess, nil
}

// Validate looks up a session by token and checks that it has not expired.
func (m *Manager) Validate(token string) (*models.Session, error) {
	row := m.db.QueryRow(
		`SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?`,
		token,
	)

	var s models.Session
	if err := row.Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("looking up session: %w", err)
	}

	if s.IsExpired(time.Now()) {
		_ = m.Destroy(s.ID)
		return nil, ErrSessionExpired
	}
	return &s, nil
}

// Refresh extends a session's expiry by the manager's configured timeout,
// implementing a sliding-window session (each command resets the clock).
func (m *Manager) Refresh(token string) (*models.Session, error) {
	newExpiry := time.Now().Add(m.timeout)
	res, err := m.db.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, newExpiry, token)
	if err != nil {
		return nil, fmt.Errorf("refreshing session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrSessionNotFound
	}
	return m.Validate(token)
}

// Destroy ends a session immediately (used by the logout command).
func (m *Manager) Destroy(token string) error {
	_, err := m.db.Exec(`DELETE FROM sessions WHERE id = ?`, token)
	return err
}
