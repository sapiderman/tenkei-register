-- Reverse the schema changes from 000004_roles.up.sql.
-- The backfill UPDATE is intentionally not reversed: it is lossy (the original
-- garbage/NULL values are gone). This restores the prior *shape*: nullable
-- role column defaulting to 'user'.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ALTER COLUMN role DROP NOT NULL;
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'user';
