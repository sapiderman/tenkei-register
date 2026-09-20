package totp

import (
	"testing"
	"time"

	libtotp "github.com/pquerna/otp/totp"
)

func testSecret(t *testing.T) string {
	t.Helper()
	key, err := libtotp.Generate(libtotp.GenerateOpts{
		Issuer:      "Tenkei Aikidojo",
		AccountName: "member@example.com",
	})
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	return key.Secret()
}

func codeAt(secret string, at time.Time) string {
	code, _ := libtotp.GenerateCode(secret, at)
	return code
}

func TestVerifyCode_CurrentStep(t *testing.T) {
	secret := testSecret(t)
	now := time.Now()

	counter, ok := VerifyCode(secret, codeAt(secret, now), now)
	if !ok {
		t.Fatal("code for the current step must verify")
	}
	if want := now.Unix() / stepSeconds; counter != want {
		t.Errorf("counter = %d, want %d", counter, want)
	}
}

func TestVerifyCode_SkewWindow(t *testing.T) {
	secret := testSecret(t)
	now := time.Now()
	step := time.Duration(stepSeconds) * time.Second

	for _, off := range []time.Duration{+step, -step} {
		at := now.Add(off)
		counter, ok := VerifyCode(secret, codeAt(secret, at), now)
		if !ok {
			t.Fatalf("code from %s (±1 step drift) must verify", off)
		}
		if want := at.Unix() / stepSeconds; counter != want {
			t.Errorf("offset %s: counter = %d, want %d", off, counter, want)
		}
	}
}

func TestVerifyCode_OutsideSkew(t *testing.T) {
	secret := testSecret(t)
	now := time.Now()
	step := time.Duration(stepSeconds) * time.Second

	for _, off := range []time.Duration{2 * step, -2 * step, 5 * step} {
		if _, ok := VerifyCode(secret, codeAt(secret, now.Add(off)), now); ok {
			t.Errorf("code from %s (beyond ±1 step) must NOT verify", off)
		}
	}
}

func TestVerifyCode_WrongCode(t *testing.T) {
	secret := testSecret(t)
	now := codeAt(secret, time.Now())

	// A syntactically valid code that is not the right one.
	wrong := "000000"
	if wrong == now {
		wrong = "000001"
	}
	if _, ok := VerifyCode(secret, wrong, time.Now()); ok {
		t.Fatal("wrong code must not verify")
	}
}

func TestVerifyCode_MalformedInput(t *testing.T) {
	secret := testSecret(t)
	now := time.Now()

	for name, code := range map[string]string{
		"empty":    "",
		"5 digits": "12345",
		"7 digits": "1234567",
		"letters":  "abcdef",
		"mixed":    "12a456",
		"padded":   " 123456",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := VerifyCode(secret, code, now); ok {
				t.Fatalf("code %q must not verify", code)
			}
		})
	}
}

func TestVerifyCode_BadSecretFailsClosed(t *testing.T) {
	// Any failure to derive a code from the secret must read as a rejected
	// code, never as a pass.
	for _, secret := range []string{"", "not-base32!!", "JBSWY3DP"} {
		if _, ok := VerifyCode(secret, "123456", time.Now()); ok {
			t.Fatalf("secret %q must fail closed", secret)
		}
	}
}
