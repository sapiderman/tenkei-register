package totp

import (
	libtotp "github.com/pquerna/otp/totp"
)

// NewSecret generates a fresh 160-bit TOTP secret with RFC 6238 defaults
// (30s period, 6 digits, SHA-1 — the profile every authenticator app speaks)
// and returns (base32 secret, otpauth:// URL). The URL is what the frontend
// renders as a QR code; the secret is shown once, at enrollment, and then
// only ever stored encrypted.
func NewSecret(issuer, accountName string) (string, string, error) {
	key, err := libtotp.Generate(libtotp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}
