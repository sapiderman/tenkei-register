package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/mailer"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// Password reset token lifecycle (PRD #24):
//   - 32 random bytes, hex-encoded; only the SHA-256 hash is stored
//     (same at-rest posture as sessions — see hashSessionID).
//   - 10-minute TTL, enforced atomically at consume time.
//   - Single-use: consumption is a conditional UPDATE ... RETURNING, so two
//     concurrent submits cannot both win.
//   - Supersede: a new request deletes the user's previous tokens.
type PasswordResetToken struct {
	bun.BaseModel `bun:"table:password_reset_tokens"`

	TokenHash string    `bun:"token_hash,pk"`
	UserID    int64     `bun:"user_id,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
	Consumed  bool      `bun:"consumed,notnull"`
}

const (
	resetTokenTTL = 10 * time.Minute
)

// Token shape: 32 bytes of CSPRNG output, hex-encoded to 64 chars — same as
// a session ID, so generateSessionID/hashSessionID are reused verbatim.

// DBPasswordResetter implements PasswordResetter over PostgreSQL + the
// shared mailer. The forgot endpoint's enumeration posture lives here:
// an unknown email is a silent no-op, and send failures never change what
// the caller sees.
type DBPasswordResetter struct {
	db       *bun.DB
	sessions SessionStore
	mailer   mailer.Mailer
	logger   zerolog.Logger
	appURL   string // web base URL for reset links, e.g. https://www.tenkeiaikidojo.org
	tmpl     *resetTemplates
}

// NewDBPasswordResetter builds the DB-backed PasswordResetter.
func NewDBPasswordResetter(db *bun.DB, sessions SessionStore, mail mailer.Mailer, logger zerolog.Logger, appURL string) *DBPasswordResetter {
	return &DBPasswordResetter{
		db:       db,
		sessions: sessions,
		mailer:   mail,
		logger:   logger,
		appURL:   strings.TrimRight(appURL, "/"),
		tmpl:     newResetTemplates(),
	}
}

// RequestReset generates and delivers a reset token for the given email.
// Unknown emails return nil — the handler's response is byte-identical
// either way, so nothing here may leak existence.
func (r *DBPasswordResetter) RequestReset(ctx context.Context, identifier string) error {
	email := strings.TrimSpace(identifier)

	var user types.User
	err := r.db.NewSelect().Model(&user).Where("email = ?", email).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("password reset: user lookup: %w", err)
	}

	// Supersede first, then insert: a failure in between leaves the user
	// with no valid token, which the next request self-heals.
	if _, err := r.db.NewDelete().
		Model((*PasswordResetToken)(nil)).
		Where("user_id = ?", user.ID).
		Exec(ctx); err != nil {
		return fmt.Errorf("password reset: supersede: %w", err)
	}

	// generateSessionID is the session token generator (32 random bytes,
	// hex). Deliberately reused: a reset token is the same class of secret.
	token, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("password reset: token generation: %w", err)
	}
	if _, err := r.db.NewInsert().Model(&PasswordResetToken{
		TokenHash: hashSessionID(token),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(resetTokenTTL),
	}).Exec(ctx); err != nil {
		return fmt.Errorf("password reset: token store: %w", err)
	}

	Audit(ctx, r.db, r.logger, user.ID, "password_reset_requested")

	r.sendResetEmailAsync(ctx, &user, token)
	return nil
}

// ConfirmReset verifies the token, consumes it atomically, rotates the
// password hash, and kills every session for the account. Distinct sentinel
// errors let the handler return stable 4xx codes the UI can map to
// "request a new link".
func (r *DBPasswordResetter) ConfirmReset(ctx context.Context, token, newPassword string) error {
	// One atomic statement enforces single-use + expiry and returns the
	// owner. An unconsumed, unexpired row flips to consumed; anything else
	// matches zero rows.
	var consumed PasswordResetToken
	err := r.db.NewRaw(
		`UPDATE password_reset_tokens SET consumed = TRUE
		  WHERE token_hash = ? AND consumed = FALSE AND expires_at > NOW()
		  RETURNING user_id`,
		hashSessionID(token),
	).Scan(ctx, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return r.classifyToken(ctx, token)
	}
	if err != nil {
		return fmt.Errorf("password reset: consume: %w", err)
	}

	// bcrypt.GenerateFromPassword cannot fail on a valid-length input; the
	// 8..72 length rule is enforced by the handler's validator.
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("password reset: hashing: %w", err)
	}
	if err := UpdateUserPassword(ctx, r.db, consumed.UserID, string(hash)); err != nil {
		// The token is already burned — the retry path is "request a new
		// link". Fail closed rather than report success for an unchanged
		// password.
		return fmt.Errorf("password reset: update: %w", err)
	}

	// Every session dies (no auto-login — the member signs in fresh). A
	// failed wipe must not hide the successful reset; it is logged and the
	// request still succeeds, mirroring the email-change path.
	if err := r.sessions.InvalidateAll(ctx, consumed.UserID); err != nil {
		r.logger.Error().Err(err).Int64("user_id", consumed.UserID).
			Msg("password reset: session invalidation failed")
	}

	Audit(ctx, r.db, r.logger, consumed.UserID, "password_reset_completed")
	return nil
}

// classifyToken distinguishes why a consume matched zero rows, for the UI's
// stable error codes. Holding a token already proves it was issued, so these
// distinctions leak nothing an attacker doesn't have.
func (r *DBPasswordResetter) classifyToken(ctx context.Context, token string) error {
	var row PasswordResetToken
	err := r.db.NewSelect().Model(&row).
		Where("token_hash = ?", hashSessionID(token)).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResetTokenInvalid // never existed, or was superseded by a newer request
	}
	if err != nil {
		return err
	}
	if row.Consumed {
		return ErrResetTokenUsed
	}
	return ErrResetTokenExpired
}

// sendResetEmailAsync delivers the reset email without blocking the 200
// response. Guardrails mirror register.sendRegistrationEmails: detached
// context (a client disconnect can't abort delivery), panic recovery that
// kills only this send, and categorized failure logging + audit. The audit
// row carries only the category — no addresses, no token.
func (r *DBPasswordResetter) sendResetEmailAsync(ctx context.Context, user *types.User, token string) {
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				r.logger.Error().Stack().
					Str("email", "reset").
					Int64("user_id", user.ID).
					Interface("panic", rec).
					Msg("panic during password reset email send")
			}
		}()

		msg, err := r.tmpl.resetMessage(user, r.resetURL(token))
		if err != nil {
			r.recordSendFailure(ctx, user, err)
			return
		}
		if err := r.mailer.Send(ctx, msg); err != nil {
			r.recordSendFailure(ctx, user, err)
		}
	}()
}

func (r *DBPasswordResetter) recordSendFailure(ctx context.Context, user *types.User, err error) {
	category := mailer.CategoryOf(err)
	r.logger.Error().
		Str("email", "reset").
		Str("to", mask(user.Email)).
		Str("category", category).
		Int64("user_id", user.ID).
		Msg("password reset email send failed")
	Audit(ctx, r.db, r.logger, user.ID, "email_send_failed:reset:"+category)
}

// resetURL builds the emailed link. English locale fixed — reset emails are
// English-only, matching every other transactional email in this app.
func (r *DBPasswordResetter) resetURL(token string) string {
	return fmt.Sprintf("%s/en/reset-password?token=%s", r.appURL, token)
}

// --- Reset email template (same engine split as register.messages: text/template
// for subject+text, html/template for the HTML body) ---

type resetTemplates struct {
	subject *texttemplate.Template
	text    *texttemplate.Template
	html    *template.Template
}

type resetEmailData struct {
	Name     string
	ResetURL string
	Minutes  int
}

const resetSubjectTmpl = `Reset your Tenkei Aikidojo password`

const resetTextTmpl = `Hi {{.Name}},

We received a request to reset the password for your Tenkei Aikidojo account. This link is valid for {{.Minutes}} minutes and can be used only once:

{{.ResetURL}}

If you did not request this, you can safely ignore this email — your password will not change.

— Tenkei Aikidojo`

const resetHTMLTmpl = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #222; max-width: 560px; margin: 0 auto;">
  <h2 style="color: #333;">Reset your password</h2>
  <p>Hi {{.Name}},</p>
  <p>We received a request to reset the password for your Tenkei Aikidojo account. This link is valid for {{.Minutes}} minutes and can be used only once:</p>
  <p><a href="{{.ResetURL}}">Reset your password</a></p>
  <p style="color: #777; font-size: 13px;">If the button does not work, copy this link into your browser:<br>{{.ResetURL}}</p>
  <p style="color: #777; font-size: 13px;">If you did not request this, you can safely ignore this email &mdash; your password will not change.</p>
  <p>&mdash; Tenkei Aikidojo</p>
</body>
</html>`

func newResetTemplates() *resetTemplates {
	return &resetTemplates{
		subject: texttemplate.Must(texttemplate.New("resetSubject").Parse(resetSubjectTmpl)),
		text:    texttemplate.Must(texttemplate.New("resetText").Parse(resetTextTmpl)),
		html:    template.Must(template.New("resetHTML").Parse(resetHTMLTmpl)),
	}
}

// resetMessage renders the password reset email.
func (t *resetTemplates) resetMessage(user *types.User, resetURL string) (mailer.Message, error) {
	data := resetEmailData{Name: user.Name, ResetURL: resetURL, Minutes: int(resetTokenTTL / time.Minute)}

	var b strings.Builder
	if err := t.subject.Execute(&b, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render resetSubject: %w", err)
	}
	subject := b.String()

	b.Reset()
	if err := t.text.Execute(&b, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render resetText: %w", err)
	}
	text := b.String()

	b.Reset()
	if err := t.html.Execute(&b, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render resetHTML: %w", err)
	}

	return mailer.Message{To: user.Email, Subject: subject, HTML: b.String(), Text: text}, nil
}
