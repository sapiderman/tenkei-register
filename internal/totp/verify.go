package totp

import (
	"time"

	otp "github.com/pquerna/otp"
	libtotp "github.com/pquerna/otp/totp"
)

// TOTP parameters, fixed for compatibility with every authenticator app
// (RFC 6238 defaults): 30-second period, 6 digits, HMAC-SHA-1. SHA-1 here is
// fine — the security of TOTP rests on the 160-bit secret, not the hash's
// collision resistance.
const (
	stepSeconds = 30
	maxSkew     = 1 // accepted clock drift, in steps, on either side
)

// VerifyCode checks a 6-digit code against the base32 secret with ±maxSkew
// steps of drift and returns the accepted step counter (unix/30). The
// counter is the caller's replay guard: persist it monotonically and reject
// anything not strictly greater than the stored value, or the same code
// would verify again inside the skew window.
//
// Each candidate step is checked with the library's ValidateCustom, one
// counter per call — the constant-time compare and the secret decoding stay
// in pquerna's code, and calling it per candidate is what makes the accepted
// step known to the caller.
//
// Failures are uniform: a bad secret, a malformed code, and a wrong code
// all return (0, false) — the caller cannot tell them apart, and neither
// can an attacker probing the endpoint.
//
// otp-plan.md sketched the signature as VerifyCode(secret, code, lastCounter,
// now); the lastCounter check moved into AcceptTOTPCounter (internal/auth) so
// replay rejection and counter persistence are one atomic UPDATE — no window
// between checking the stored counter and storing the new one.
func VerifyCode(secretBase32, code string, at time.Time) (int64, bool) {
	step := at.Unix() / stepSeconds
	// Highest candidate first: a code valid across a step boundary burns the
	// larger counter, which is the conservative choice for replay defense.
	for _, off := range [maxSkew*2 + 1]int64{maxSkew, 0, -maxSkew} {
		counter := step + off
		ok, err := libtotp.ValidateCustom(
			code,
			secretBase32,
			time.Unix(counter*stepSeconds, 0),
			libtotp.ValidateOpts{
				Period:    stepSeconds,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
				Skew:      0, // the loop is the skew: exactly one candidate per call
			},
		)
		if err != nil {
			return 0, false // malformed code or secret — fail closed
		}
		if ok {
			return counter, true
		}
	}
	return 0, false
}
