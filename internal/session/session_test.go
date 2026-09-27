package session

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE);
CREATE TABLE sessions (
    id                  TEXT PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          DATETIME NOT NULL
);
`

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("applying schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, username) VALUES (1, 'testuser')`); err != nil {
		t.Fatalf("seeding user: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateAndValidate(t *testing.T) {
	m := NewManager(newTestDB(t), time.Hour)
	sess, err := m.Create(1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}

	got, err := m.Validate(sess.ID)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got.UserID != 1 {
		t.Errorf("UserID = %d, want 1", got.UserID)
	}
}

func TestValidate_NotFound(t *testing.T) {
	m := NewManager(newTestDB(t), time.Hour)
	_, err := m.Validate("nonexistent-token")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate() error = %v, want ErrSessionNotFound", err)
	}
}

func TestValidate_Expired(t *testing.T) {
	m := NewManager(newTestDB(t), 10*time.Millisecond)
	sess, err := m.Create(1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	_, err = m.Validate(sess.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Validate() error = %v, want ErrSessionExpired", err)
	}

	// An expired session should also be cleaned up (deleted), so a second
	// lookup reports "not found" rather than "expired".
	_, err = m.Validate(sess.ID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second Validate() error = %v, want ErrSessionNotFound", err)
	}
}

func TestRefresh_ExtendsExpiry(t *testing.T) {
	m := NewManager(newTestDB(t), 50*time.Millisecond)
	sess, err := m.Create(1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	originalExpiry := sess.ExpiresAt

	time.Sleep(20 * time.Millisecond)
	refreshed, err := m.Refresh(sess.ID)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !refreshed.ExpiresAt.After(originalExpiry) {
		t.Errorf("refreshed expiry %v should be after original %v", refreshed.ExpiresAt, originalExpiry)
	}
}

func TestDestroy(t *testing.T) {
	m := NewManager(newTestDB(t), time.Hour)
	sess, err := m.Create(1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := m.Destroy(sess.ID); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
	_, err = m.Validate(sess.ID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate() after Destroy() error = %v, want ErrSessionNotFound", err)
	}
}

func TestCreate_ReplacesPriorSession(t *testing.T) {
	m := NewManager(newTestDB(t), time.Hour)
	first, err := m.Create(1)
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	second, err := m.Create(1)
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}

	if _, err := m.Validate(first.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("old session should be invalidated, got err = %v", err)
	}
	if _, err := m.Validate(second.ID); err != nil {
		t.Errorf("new session should be valid, got err = %v", err)
	}
}
