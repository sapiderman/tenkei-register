-- Account deletion one-time codes for the self-deletion flow (PRD #25).
-- Only the SHA-256 hex of the emailed 6-digit code is stored — the same
-- at-rest posture as password-reset tokens (000006). A code is single-use
-- (consumed flag), short-lived (10 minutes, enforced at consume time), and
-- capped at 5 wrong submissions (attempts, enforced at consume time).
-- Requesting a new code supersedes the previous one by deletion (see
-- internal/auth/delete_code.go).

CREATE TABLE IF NOT EXISTS account_deletion_codes (
    user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed   BOOLEAN NOT NULL DEFAULT FALSE,
    attempts   INT NOT NULL DEFAULT 0,
    -- Composite key, not a global one: the code space is 10^6, so a
    -- table-wide unique hash would collide across users as rows accumulate
    -- (consumed rows are never pruned). Uniqueness only matters per user.
    PRIMARY KEY (user_id, code_hash)
);

-- Idempotent index creation. No standalone user_id index: the composite
-- PK's leading column already serves the user_id lookups in delete_code.go.
CREATE INDEX IF NOT EXISTS idx_account_deletion_codes_expires_at ON account_deletion_codes(expires_at);

-- At most one live (unconsumed) code per user, enforced by the database:
-- same rationale as uq_password_reset_tokens_live_user — delete-then-insert
-- alone is not atomic, so concurrent requests could both insert; the code
-- retries on this conflict (last request wins).
CREATE UNIQUE INDEX IF NOT EXISTS uq_account_deletion_codes_live_user
    ON account_deletion_codes(user_id)
    WHERE consumed = FALSE;
