-- Email becomes the sole login identifier (PRD: Member Profile Editing +
-- Email-as-Sole-Login-Identifier). WhatsApp is demoted to an optional,
-- non-unique profile field. Production is confirmed clear of null/empty
-- emails, so the NOT NULL cutover needs no backfill.

ALTER TABLE users ALTER COLUMN email SET NOT NULL;
ALTER TABLE users ALTER COLUMN whatsapp_number DROP NOT NULL;
DROP INDEX IF EXISTS users_whatsapp_idx;
