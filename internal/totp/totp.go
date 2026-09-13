// Package totp provides the cryptographic primitives for TOTP two-factor
// authentication: an AES-256-GCM cipher for the shared secret at rest and
// (later phases of otp-plan.md) code generation and verification.
//
// The encryption key never lives in the database — a DB read or backup leak
// alone must not yield secrets usable to generate codes.
package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// keySize is the AES-256 key length in bytes. Generate one with:
//
//	openssl rand -base64 32
const keySize = 32

// ErrInvalidKey is returned when the configured key is not decodable base64
// naming exactly 32 bytes. It is a configuration error, not a data error.
var ErrInvalidKey = errors.New("totp: encryption key must be base64-encoded 32 bytes")

// ParseKey decodes the configured encryption key (base64 → 32 bytes). The
// trailing base64 padding '=' is trimmed first so a 43-character unpadded
// key (common with some secret managers) is accepted too.
func ParseKey(s string) ([]byte, error) {
	raw := strings.TrimSpace(s)
	raw = strings.TrimRight(raw, "=")
	key, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(key) != keySize {
		return nil, ErrInvalidKey
	}
	return key, nil
}

// EncryptSecret seals plaintext with AES-256-GCM and returns
// base64(nonce || ciphertext+tag). The GCM authentication tag makes any
// tampering with the stored value detectable at decrypt time.
func EncryptSecret(key []byte, plaintext string) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("totp: nonce generation: %w", err)
	}
	sealed := aead.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// DecryptSecret opens a value produced by EncryptSecret. It fails closed on
// a wrong key, truncation, or tampering — callers treat any error as
// "enrollment is unreadable", never as plaintext passthrough.
func DecryptSecret(key []byte, encoded string) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("totp: secret is not valid base64: %w", err)
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("totp: encrypted secret is truncated")
	}
	plaintext, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("totp: decrypt: %w", err)
	}
	return string(plaintext), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("totp: cipher init: %w", err)
	}
	return cipher.NewGCM(block)
}
