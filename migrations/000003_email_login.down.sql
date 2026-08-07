-- Best-effort reverse of 000003_email_login.up.sql.
-- The whatsapp_number SET NOT NULL (and therefore the unique index restore)
-- FAILS if any row has a NULL whatsapp_number; email DROP NOT NULL is always safe.

ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ALTER COLUMN whatsapp_number SET NOT NULL;
CREATE UNIQUE INDEX users_whatsapp_idx ON users USING btree (whatsapp_number);
