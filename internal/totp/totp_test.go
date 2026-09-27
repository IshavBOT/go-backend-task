package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateSecret(t *testing.T) {
	secret, uri, err := GenerateSecret("TestIssuer", "alice")
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	if secret == "" {
		t.Error("expected non-empty secret")
	}
	if !strings.Contains(uri, "otpauth://totp/") {
		t.Errorf("uri = %q, want otpauth:// scheme", uri)
	}
	if !strings.Contains(uri, "TestIssuer") {
		t.Errorf("uri = %q, want to contain issuer", uri)
	}
}

func TestValidate_CorrectCode(t *testing.T) {
	secret, _, err := GenerateSecret("TestIssuer", "bob")
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}
	if !Validate(code, secret) {
		t.Error("Validate() = false, want true for a freshly generated code")
	}
}

func TestValidate_WrongCode(t *testing.T) {
	secret, _, err := GenerateSecret("TestIssuer", "carol")
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	if Validate("000000", secret) {
		t.Error("Validate() = true for an arbitrary wrong code, want false (astronomically unlikely to be correct)")
	}
}

func TestValidate_BadSecret(t *testing.T) {
	if Validate("123456", "not-a-valid-base32-secret!!!") {
		t.Error("Validate() = true for an invalid secret, want false")
	}
}
