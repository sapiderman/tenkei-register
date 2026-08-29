// Package turnstile verifies Cloudflare Turnstile tokens server-side.
// See: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
//
// It is verified inline in the handlers that need it (registration, login),
// not as middleware — each route decides whether it applies.
package turnstile

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/middleware"
)

const defaultVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Verifier validates Cloudflare Turnstile tokens against the siteverify API.
type Verifier struct {
	logger  zerolog.Logger
	secret  string
	enabled bool

	// VerifyURL overrides the Cloudflare siteverify endpoint. Zero value
	// falls back to the real URL in Verify; tests set this to a
	// httptest.Server URL.
	VerifyURL string
}

// New builds a Verifier from server config values.
func New(secret string, enabled bool, logger zerolog.Logger) *Verifier {
	return &Verifier{logger: logger, secret: secret, enabled: enabled}
}

// Verify checks a Turnstile token. It returns nil when verification is
// disabled (dev bypass) or the token validates; otherwise a non-nil error.
func (v *Verifier) Verify(req *http.Request, token string) error {
	// Check if turnstile verification is enabled first; bypass if disabled
	if !v.enabled {
		v.logger.Debug().Caller().Msg("Bypassing Turnstile verification")
		return nil
	}

	// If enabled, validate required fields
	if token == "" {
		v.logger.Warn().Msg("Turnstile token is empty")
		return errors.New("turnstile token is empty")
	}

	if v.secret == "" {
		v.logger.Error().Msg("TURNSTILE_SECRET_KEY not configured")
		return errors.New("TURNSTILE_SECRET_KEY not configured")
	}

	form := url.Values{}
	form.Add("secret", v.secret)
	form.Add("response", token)

	// Add trusted client IP for Turnstile verification: CF-Connecting-IP
	// when behind Cloudflare, else RemoteAddr (see middleware.ClientIP).
	remoteIP := middleware.ClientIP(req)
	if remoteIP != "" {
		form.Add("remoteip", remoteIP)
	}

	v.logger.Debug().
		Str("remoteIP", remoteIP).
		Msg("Sending Turnstile verification request")

	verifyURL := v.VerifyURL
	if verifyURL == "" {
		verifyURL = defaultVerifyURL
	}
	resp, err := http.PostForm(verifyURL, form) // #nosec G107,G704 — verifyURL is config-derived (TENKEI_SERVER_TURNSTILE_*), never request-controlled
	if err != nil {
		v.logger.Error().
			Err(err).
			Str("remoteIP", remoteIP).
			Msg("Turnstile HTTP request failed")
		return err
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		v.logger.Error().
			Int("statusCode", resp.StatusCode).
			Str("status", resp.Status).
			Msg("Turnstile API returned non-OK status")
		return errors.New("turnstile API returned non-OK status: " + resp.Status)
	}

	// Cloudflare Turnstile response structure
	// See: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
	var result struct {
		Success     bool     `json:"success"`
		ChallengeTS string   `json:"challenge_ts"` // ISO timestamp of challenge
		Hostname    string   `json:"hostname"`     // Hostname of site where challenge was solved
		ErrorCodes  []string `json:"error-codes"`  // Error codes if verification failed
		Action      string   `json:"action"`       // Action name (if configured)
		CData       string   `json:"cdata"`        // Custom data (if configured)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		v.logger.Error().
			Err(err).
			Int("statusCode", resp.StatusCode).
			Msg("Failed to decode Turnstile response")
		return errors.New("failed to decode turnstile response: " + err.Error())
	}

	// Log the full response details for debugging
	logEvent := v.logger.Debug().
		Bool("success", result.Success).
		Str("hostname", result.Hostname).
		Str("challengeTS", result.ChallengeTS).
		Str("remoteIP", remoteIP)

	if result.Action != "" {
		logEvent = logEvent.Str("action", result.Action)
	}
	if result.CData != "" {
		logEvent = logEvent.Str("cdata", result.CData)
	}
	if len(result.ErrorCodes) > 0 {
		logEvent = logEvent.Strs("errorCodes", result.ErrorCodes)
	}
	logEvent.Msg("Turnstile verification response")

	if !result.Success {
		// Log error with detailed information from Cloudflare
		errLogger := v.logger.Error().
			Strs("errorCodes", result.ErrorCodes).
			Str("hostname", result.Hostname).
			Str("challengeTS", result.ChallengeTS).
			Str("remoteIP", remoteIP)

		// Provide human-readable error descriptions
		var errorDescriptions []string
		for _, code := range result.ErrorCodes {
			switch code {
			case "missing-input-secret":
				errorDescriptions = append(errorDescriptions, "The secret parameter was not passed")
			case "invalid-input-secret":
				errorDescriptions = append(errorDescriptions, "The secret parameter was invalid or did not exist")
			case "missing-input-response":
				errorDescriptions = append(errorDescriptions, "The response parameter was not passed")
			case "invalid-input-response":
				errorDescriptions = append(errorDescriptions, "The response parameter is invalid or has expired")
			case "bad-request":
				errorDescriptions = append(errorDescriptions, "The request was rejected because it was malformed")
			case "timeout-or-duplicate":
				errorDescriptions = append(errorDescriptions, "The response parameter has already been validated before or is too old")
			case "internal-error":
				errorDescriptions = append(errorDescriptions, "An internal error happened while validating the response (retry)")
			default:
				errorDescriptions = append(errorDescriptions, "Unknown error: "+code)
			}
		}

		if len(errorDescriptions) > 0 {
			errLogger = errLogger.Strs("errorDescriptions", errorDescriptions)
		}

		errLogger.Msg("Turnstile verification failed")
		return errors.New("turnstile verification failed: " + strings.Join(result.ErrorCodes, ", "))
	}

	v.logger.Info().
		Str("hostname", result.Hostname).
		Str("remoteIP", remoteIP).
		Msg("Turnstile verification successful")

	return nil
}
