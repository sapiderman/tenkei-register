-- Reverse 000008_totp.up.sql. Dropping the columns disables TOTP outright:
-- with the columns gone the verifier's totp_enabled read is simply absent,
-- and every account falls back to password-only login. Enrollment is
-- re-doable, so no data preservation is needed.

ALTER TABLE users
    DROP COLUMN totp_secret,
    DROP COLUMN totp_enabled,
    DROP COLUMN totp_last_counter;

ALTER TABLE sessions
    DROP COLUMN totp_attempts;
