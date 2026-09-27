// Package totp wraps TOTP (RFC 6238) secret generation and verification,
// producing secrets and provisioning URIs compatible with Google
// Authenticator, Authy, and similar apps.
package totp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateSecret creates a new random TOTP secret for the given account and
// issuer, returning both the base32 secret (for manual entry) and the full
// otpauth:// provisioning URI (which can be rendered as a QR code by any
// standard authenticator app, or pasted into apps that accept a URI).
func GenerateSecret(issuer, accountName string) (secret string, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("generating TOTP secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Validate checks a 6-digit TOTP code against a base32 secret, allowing the
// standard +/-1 time-step skew to tolerate minor clock drift between the
// server and the user's authenticator app.
func Validate(code, secret string) bool {
	valid, _ := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}
