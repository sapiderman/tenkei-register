-- Password reset tokens for the forgot/reset-password flow (PRD #24).
-- Only the SHA-256 hex of the emailed token is stored — the same at-rest
-- posture as session tokens (sessions.id). A token is single-use (consumed
-- flag) and short-lived (10 minutes, enforced at consume time). Requesting
-- a new token supersedes the previous one by deletion (see internal/auth/reset.go).

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash  VARCHAR(64) PRIMARY KEY,
    user_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE
);

-- Idempotent index creation
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
