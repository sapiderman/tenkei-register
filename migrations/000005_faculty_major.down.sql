-- Reverse the schema change from 000005_faculty_major.up.sql.
-- The dojo re-label is intentionally not reversed: it is lossy (new rows may
-- already carry the canonical spelling) and mirrors the 000004 convention.
ALTER TABLE users DROP COLUMN IF EXISTS "faculty";
ALTER TABLE users DROP COLUMN IF EXISTS "major";
