-- TOTP second-factor columns (see otp-plan.md, Phase 1).
--
-- users.totp_secret       AES-256-GCM encrypted base32 secret. The encryption
--                         key lives in app config (TENKEI_TOTP_ENCRYPTION_KEY),
--                         never in the database: a DB read or backup leak alone
--                         yields no secret usable to generate codes. NULL means
--                         never enrolled; the application never stores ''.
-- users.totp_enabled      FALSE until the member confirms enrollment by
--                         submitting a first valid code — an unconfirmed
--                         enrollment must never gate login.
-- users.totp_last_counter Highest TOTP step accepted for this user. A code
--                         stays valid across the ±1 step skew window, so the
--                         same code would otherwise verify twice; verification
--                         accepts a step only if strictly greater than this
--                         value (monotonic replay guard). 0 is the "never
--                         used" sentinel — real steps (unix/30) are in the
--                         tens of millions.
-- sessions.totp_attempts  Failed code attempts on a pending (unverified)
--                         session. The verify handler deletes the session row
--                         at 5, so a stolen pending cookie cannot keep
--                         brute-forcing 6-digit codes.
--
-- No index needed: every access is by users.id or sessions.id primary key.

ALTER TABLE users
    ADD COLUMN totp_secret       TEXT,
    ADD COLUMN totp_enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_last_counter BIGINT NOT NULL DEFAULT 0;

ALTER TABLE sessions
    ADD COLUMN totp_attempts INT NOT NULL DEFAULT 0;
