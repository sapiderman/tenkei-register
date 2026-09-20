package totp

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey() []byte {
	return bytes.Repeat([]byte{0x42}, keySize)
}

func TestParseKey(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(testKey())

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid padded", valid, false},
		{"valid unpadded", strings.TrimRight(valid, "="), false},
		{"valid with whitespace", "  " + valid + "\n", false},
		{"empty", "", true},
		{"not base64", "!!!not-base64!!!", true},
		{"wrong length 16 bytes", base64.StdEncoding.EncodeToString(make([]byte, 16)), true},
		{"wrong length 64 bytes", base64.StdEncoding.EncodeToString(make([]byte, 64)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseKey(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseKey(%q): expected error, got key of %d bytes", tt.in, len(key))
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKey(%q): %v", tt.in, err)
			}
			if len(key) != keySize {
				t.Fatalf("ParseKey(%q): got %d bytes, want %d", tt.in, len(key), keySize)
			}
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := testKey()
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // a 160-bit base32 secret

	enc, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if enc == "" || enc == secret {
		t.Fatal("ciphertext must be non-empty and differ from plaintext")
	}
	dec, err := DecryptSecret(key, enc)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if dec != secret {
		t.Fatalf("round-trip mismatch: got %q, want %q", dec, secret)
	}
}

func TestEncrypt_RandomNonce(t *testing.T) {
	// Same plaintext, same key → different ciphertexts (fresh nonce per call).
	// A fixed nonce would let an attacker detect two users sharing a secret.
	key := testKey()
	a, err := EncryptSecret(key, "same-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	b, err := EncryptSecret(key, "same-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if a == b {
		t.Fatal("expected different ciphertexts for the same plaintext (nonce reuse)")
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	enc, err := EncryptSecret(testKey(), "some-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if _, err := DecryptSecret(bytes.Repeat([]byte{0x00}, keySize), enc); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}
}

func TestDecrypt_TruncatedFails(t *testing.T) {
	enc, err := EncryptSecret(testKey(), "some-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)

	tests := map[string]string{
		"empty":          "",
		"nonce only":     base64.StdEncoding.EncodeToString(raw[:12]),
		"one byte short": base64.StdEncoding.EncodeToString(raw[:len(raw)-1]),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecryptSecret(testKey(), in); err == nil {
				t.Fatalf("DecryptSecret(%s): expected error", name)
			}
		})
	}
}

func TestDecrypt_TamperedFails(t *testing.T) {
	enc, err := EncryptSecret(testKey(), "some-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	raw[len(raw)-1] ^= 0xFF // flip a bit inside the GCM tag
	if _, err := DecryptSecret(testKey(), base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered ciphertext must fail GCM authentication")
	}
}

func TestEncrypt_WrongKeySizeFails(t *testing.T) {
	if _, err := EncryptSecret(make([]byte, 16), "x"); err == nil {
		t.Fatal("EncryptSecret with 16-byte key must fail")
	}
}
