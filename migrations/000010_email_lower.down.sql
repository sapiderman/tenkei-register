-- Reverse the schema change from 000010_email_lower.up.sql.
-- The lowercasing is intentionally not reversed: lower() is lossy (the
-- original mixed-case spellings cannot be reconstructed), mirroring the
-- 000005/000007 convention. Application code keeps lowercasing every write
-- and matching every lookup on lower(email), so the raw index restored here
-- is a weaker uniqueness guarantee than the functional one it replaces.
DROP INDEX users_email_lower_idx;
CREATE UNIQUE INDEX users_email_idx ON users USING btree (email);
