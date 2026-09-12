-- Reverse the schema change from 000007_phone_e164.up.sql.
-- The E.164 normalization is intentionally not reversed: it is lossy (the
-- original mixed-format spellings — "08...", "62...", "+62..." — cannot be
-- reconstructed) and mirrors the 000005 convention. Application code keeps
-- accepting all three input shapes and stores E.164 either way.
SELECT 1; -- no-op
