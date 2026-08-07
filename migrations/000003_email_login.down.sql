-- Best-effort reverse of 000003_email_login.up.sql. Two distinct preconditions
-- must hold for this to succeed:
--   * whatsapp_number SET NOT NULL fails if ANY row has a NULL whatsapp_number.
--   * CREATE UNIQUE INDEX fails if any DUPLICATE non-NULL whatsapp_number exists
--     (Postgres unique indexes allow multiple NULLs, so NULLs are not the blocker
--     for this step - duplicates are). This is the likely failure mode once the
--     up-migration has been live, since members sharing a number is intentionally
--     allowed by 000003.
-- To roll back: backfill/deduplicate whatsapp_number first.
-- email DROP NOT NULL is always safe.

ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ALTER COLUMN whatsapp_number SET NOT NULL;
CREATE UNIQUE INDEX users_whatsapp_idx ON users USING btree (whatsapp_number);
