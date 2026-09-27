package auth

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "embed"

	_ "github.com/mattn/go-sqlite3"
)

// schema mirrors migrations/001_init.sql for isolated, in-memory test databases.
const schema = `
CREATE TABLE users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    totp_secret         TEXT,
    totp_enabled        INTEGER NOT NULL DEFAULT 0,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        DATETIME,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at       DATETIME
);
CREATE TABLE sessions (
    id                  TEXT PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          DATETIME NOT NULL
);
`

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Each test gets its own uniquely-named in-memory database so tests
	// never interfere with one another.
	db, err := sql.Open("sqlite3", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("applying schema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestService(t *testing.T) *Service {
	return NewService(newTestDB(t), 4 /* low bcrypt cost for fast tests */, 3, 100*time.Millisecond)
}

func TestRegister_Success(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("alice", "password123"); err != nil {
		t.Fatalf("Register() error = %v, want nil", err)
	}
	u, err := s.GetByUsername("alice")
	if err != nil {
		t.Fatalf("GetByUsername() error = %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("got username %q, want alice", u.Username)
	}
	if u.PasswordHash == "password123" {
		t.Errorf("password was stored in plaintext")
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("bob", "password123"); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	err := s.Register("bob", "anotherpassword")
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("Register() duplicate error = %v, want ErrUserExists", err)
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	s := newTestService(t)
	cases := []string{"ab", "has space", "way-too-long-a-username-for-this-system-to-accept-ok"}
	for _, username := range cases {
		if err := s.Register(username, "password123"); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("Register(%q) error = %v, want ErrInvalidUsername", username, err)
		}
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("carol", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Register() error = %v, want ErrWeakPassword", err)
	}
}

func TestVerifyPassword_Success(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("dave", "correcthorse"); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	u, err := s.VerifyPassword("dave", "correcthorse")
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v, want nil", err)
	}
	if u.Username != "dave" {
		t.Errorf("got username %q, want dave", u.Username)
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("erin", "correcthorse"); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	_, err := s.VerifyPassword("erin", "wrongpassword")
	if !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("VerifyPassword() error = %v, want ErrInvalidCreds", err)
	}
}

func TestVerifyPassword_UnknownUserDoesNotLeak(t *testing.T) {
	s := newTestService(t)
	_, err := s.VerifyPassword("nosuchuser", "whatever")
	if !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("VerifyPassword() error = %v, want ErrInvalidCreds (not ErrUserNotFound)", err)
	}
}

func TestAccountLockout(t *testing.T) {
	s := newTestService(t) // maxFailedAttempts = 3, lockoutDuration = 100ms
	if err := s.Register("frank", "correcthorse"); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Two failed attempts: still allowed, not yet locked.
	for i := 0; i < 2; i++ {
		if _, err := s.VerifyPassword("frank", "wrong"); !errors.Is(err, ErrInvalidCreds) {
			t.Fatalf("attempt %d: error = %v, want ErrInvalidCreds", i, err)
		}
	}

	// Third failed attempt crosses the threshold and locks the account.
	if _, err := s.VerifyPassword("frank", "wrong"); !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("3rd attempt: error = %v, want ErrInvalidCreds", err)
	}

	// Even the correct password is now rejected because the account is locked.
	if _, err := s.VerifyPassword("frank", "correcthorse"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked login: error = %v, want ErrAccountLocked", err)
	}

	// After the lockout duration elapses, correct credentials work again.
	time.Sleep(150 * time.Millisecond)
	if _, err := s.VerifyPassword("frank", "correcthorse"); err != nil {
		t.Fatalf("post-lockout login: error = %v, want nil", err)
	}
}

func TestVerifyPassword_ResetsFailedAttemptsOnSuccess(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("grace", "correcthorse"); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, err := s.VerifyPassword("grace", "wrong"); !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("failed login error = %v", err)
	}
	if _, err := s.VerifyPassword("grace", "correcthorse"); err != nil {
		t.Fatalf("successful login error = %v", err)
	}
	u, err := s.GetByUsername("grace")
	if err != nil {
		t.Fatalf("GetByUsername() error = %v", err)
	}
	if u.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d, want 0 after successful login", u.FailedAttempts)
	}
}

func TestTOTPEnableDisable(t *testing.T) {
	s := newTestService(t)
	if err := s.Register("heidi", "correcthorse"); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	u, _ := s.GetByUsername("heidi")

	if err := s.SetTOTPSecret(u.ID, "SECRETBASE32", true); err != nil {
		t.Fatalf("SetTOTPSecret() error = %v", err)
	}
	u, _ = s.GetByUsername("heidi")
	if !u.TOTPEnabled || u.TOTPSecret != "SECRETBASE32" {
		t.Fatalf("TOTP not enabled correctly: enabled=%v secret=%q", u.TOTPEnabled, u.TOTPSecret)
	}

	if err := s.DisableTOTP(u.ID); err != nil {
		t.Fatalf("DisableTOTP() error = %v", err)
	}
	u, _ = s.GetByUsername("heidi")
	if u.TOTPEnabled || u.TOTPSecret != "" {
		t.Fatalf("TOTP not disabled correctly: enabled=%v secret=%q", u.TOTPEnabled, u.TOTPSecret)
	}
}
