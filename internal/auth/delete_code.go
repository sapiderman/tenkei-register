package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/sapiderman/tenkei-register/internal/mailer"
	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// Account deletion code lifecycle (PRD #25) — same one-shot token state
// machine as PasswordResetToken (reset.go), plus an attempts counter:
//   - 6 digits from crypto/rand; only the SHA-256 hash is stored (same
//     at-rest posture as sessions and reset tokens — see hashSessionID).
//   - 10-minute TTL, enforced atomically at consume time.
//   - Single-use: consumption is a conditional UPDATE ... RETURNING, so two
//     concurrent submits cannot both win.
//   - At most 5 wrong submissions per code; the consume predicate carries
//     the guard, so the sixth guess can never win even with the right code.
//   - Supersede: a new request deletes the user's previous codes; the
//     partial unique index uq_account_deletion_codes_live_user enforces at
//     most one live code per user, with a bounded retry in issueDeletionCode.
type AccountDeletionCode struct {
	bun.BaseModel `bun:"table:account_deletion_codes"`

	UserID    int64     `bun:"user_id,pk"`
	CodeHash  string    `bun:"code_hash,pk"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
	Consumed  bool      `bun:"consumed,notnull"`
	Attempts  int       `bun:"attempts,notnull"`
}

const (
	deletionCodeTTL         = 10 * time.Minute
	maxDeletionCodeAttempts = 5
)

// generateDeletionCode draws a uniformly random 6-digit code (000000–999999).
// Rejection sampling, never modulo of one big draw: 2^32 is not a multiple
// of 10^6, so % would favor the low codes. Values at or above the largest
// multiple of 10^6 below 2^32 are redrawn, leaving every code with exactly
// 4294 preimages.
func generateDeletionCode() (string, error) {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("deletion code: generation: %w", err)
		}
		if n := binary.BigEndian.Uint32(b[:]); n < 4294000000 {
			return fmt.Sprintf("%06d", n%1000000), nil
		}
	}
}

// issueDeletionCode supersedes any previous code and stores a fresh one.
// Copy of issueToken's shape — see reset.go for the delete-then-insert
// contention story (last request wins).
func issueDeletionCode(ctx context.Context, db *bun.DB, userID int64) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		// Supersede first, then insert: a failure in between leaves the user
		// with no valid code, which the next request self-heals.
		if _, err := db.NewDelete().
			Model((*AccountDeletionCode)(nil)).
			Where("user_id = ?", userID).
			Exec(ctx); err != nil {
			return "", fmt.Errorf("deletion code: supersede: %w", err)
		}

		code, err := generateDeletionCode()
		if err != nil {
			return "", err
		}
		_, err = db.NewInsert().Model(&AccountDeletionCode{
			CodeHash:  hashSessionID(code),
			UserID:    userID,
			ExpiresAt: time.Now().Add(deletionCodeTTL),
		}).Exec(ctx)
		if err == nil {
			return code, nil
		}
		if !isUniqueViolation(err) {
			return "", fmt.Errorf("deletion code: store: %w", err)
		}
		// A concurrent request won the race; its row dies on the next
		// iteration's delete and this request retries.
	}
	return "", fmt.Errorf("deletion code: store: supersede contention")
}

// consumeDeletionCode verifies and burns the code atomically. One statement
// enforces hash match + live + unexpired + attempts left, so two concurrent
// submits cannot both win. A miss increments the live code's attempt
// counter, but the caller only ever learns false for wrong, exhausted,
// expired and superseded codes alike — the request is session-authenticated,
// so there is nothing to enumerate; the handler answers the same plain 400.
// Infrastructure failures return a non-nil error so the handler can fail
// closed with a 500 instead of masquerading as a wrong code.
func consumeDeletionCode(ctx context.Context, db *bun.DB, userID int64, code string) (bool, error) {
	var consumedUserID int64
	err := db.NewRaw(
		`UPDATE account_deletion_codes SET consumed = TRUE
		  WHERE user_id = ? AND code_hash = ? AND consumed = FALSE
		    AND expires_at > NOW() AND attempts < ?
		  RETURNING user_id`,
		userID, hashSessionID(code), maxDeletionCodeAttempts,
	).Scan(ctx, &consumedUserID)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("deletion code: consume: %w", err)
	}

	// Wrong code against a live row: burn one attempt, capped at the budget
	// so the counter stops at the limit. Zero rows updated means
	// expired/none/superseded — nothing left to count either way.
	_, _ = db.NewRaw(
		`UPDATE account_deletion_codes SET attempts = attempts + 1
		  WHERE user_id = ? AND consumed = FALSE AND expires_at > NOW()
		    AND attempts < ?`,
		userID, maxDeletionCodeAttempts,
	).Exec(ctx)
	return false, nil
}

// sendDeletionCodeEmail delivers the code inside the request, mirroring
// sendResetEmail (reset.go): detached context, panic recovery, categorized
// failure audit. The Cloud Run rationale is documented there — a detached
// goroutine starves at scale-to-zero, so the send rides the request.
func (a *authenticator) sendDeletionCodeEmail(ctx context.Context, user *types.User, code string) {
	ctx = context.WithoutCancel(ctx)
	defer func() {
		if rec := recover(); rec != nil {
			a.logger.Error().Stack().
				Str("email", "deletion-code").
				Int64("user_id", user.ID).
				Interface("panic", rec).
				Msg("panic during deletion code email send")
		}
	}()

	msg, err := a.delTmpl.deletionMessage(user, code)
	if err != nil {
		a.recordDeletionSendFailure(ctx, user, err)
		return
	}
	if err := a.mailer.Send(ctx, msg); err != nil {
		a.recordDeletionSendFailure(ctx, user, err)
	}
}

func (a *authenticator) recordDeletionSendFailure(ctx context.Context, user *types.User, err error) {
	category := mailer.CategoryOf(err)
	a.logger.Error().
		Str("email", "deletion-code").
		Str("to", server.Mask(user.Email)).
		Str("category", category).
		Int64("user_id", user.ID).
		Msg("deletion code email send failed")
	Audit(ctx, a.db, a.logger, user.ID, "email_send_failed:deletion_code:"+category)
}

// --- Deletion code email template (same engine split as reset.go: text/template
// for subject+text, html/template for the HTML body; English locale fixed —
// every transactional email in this app is English-only) ---

type deletionTemplates struct {
	subject *texttemplate.Template
	text    *texttemplate.Template
	html    *template.Template
}

type deletionEmailData struct {
	Name    string
	Code    string
	Minutes int
}

const deletionSubjectTmpl = `Your Tenkei account deletion code`

const deletionTextTmpl = `Hi {{.Name}},

You asked to permanently delete your Tenkei Aikidojo account. Enter this code to confirm the deletion:

{{.Code}}

This code expires in {{.Minutes}} minutes and can be used only once.

If you did not request this, you can safely ignore this email — nothing happens.

— Tenkei Aikidojo`

const deletionHTMLTmpl = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #222; max-width: 560px; margin: 0 auto;">
  <h2 style="color: #333;">Delete your account</h2>
  <p>Hi {{.Name}},</p>
  <p>You asked to permanently delete your Tenkei Aikidojo account. Enter this code to confirm the deletion:</p>
  <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px;">{{.Code}}</p>
  <p>This code expires in {{.Minutes}} minutes and can be used only once.</p>
  <p style="color: #777; font-size: 13px;">If you did not request this, you can safely ignore this email &mdash; nothing happens.</p>
  <p>&mdash; Tenkei Aikidojo</p>
</body>
</html>`

func newDeletionTemplates() *deletionTemplates {
	return &deletionTemplates{
		subject: texttemplate.Must(texttemplate.New("deletionSubject").Parse(deletionSubjectTmpl)),
		text:    texttemplate.Must(texttemplate.New("deletionText").Parse(deletionTextTmpl)),
		html:    template.Must(template.New("deletionHTML").Parse(deletionHTMLTmpl)),
	}
}

// deletionMessage renders the deletion code email.
func (t *deletionTemplates) deletionMessage(user *types.User, code string) (mailer.Message, error) {
	data := deletionEmailData{Name: user.Name, Code: code, Minutes: int(deletionCodeTTL / time.Minute)}

	var b strings.Builder
	if err := t.subject.Execute(&b, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render deletionSubject: %w", err)
	}
	subject := b.String()

	b.Reset()
	if err := t.text.Execute(&b, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render deletionText: %w", err)
	}
	text := b.String()

	b.Reset()
	if err := t.html.Execute(&b, data); err != nil {
		return mailer.Message{}, fmt.Errorf("render deletionHTML: %w", err)
	}

	return mailer.Message{To: user.Email, Subject: subject, HTML: b.String(), Text: text}, nil
}
