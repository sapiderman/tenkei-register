-- Reverse 000009_user_category.up.sql by dropping the four category columns.
-- The student backfill is not reversible (rows created after the up may have
-- edited university freely), so down = data loss for post-launch category
-- data — never run down in production casually.
ALTER TABLE users
    DROP COLUMN IF EXISTS category,
    DROP COLUMN IF EXISTS university,
    DROP COLUMN IF EXISTS school_name,
    DROP COLUMN IF EXISTS guardian_name;
