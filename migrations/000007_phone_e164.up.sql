-- Normalize phone columns to E.164 international format (+62...), matching the
-- application-side types.NormalizePhone used by registration and profile
-- updates.
--
-- Step 1 strips separators (space, non-breaking space, dash, dot, parenthesis).
-- Step 2 removes Indonesia's national trunk prefix when it sits right after the
-- country code: "+62 0812..." and "620812..." are the same number as
-- "+62812...". E.164 keeps no trunk prefix after the country code, so a stored
-- "+620812..." is undialable.
--
-- A value is then rewritten only if it matches a shape the application accepts:
--   "+62..." on the Indonesian numbering plan          → kept
--   "+<other country code>..." (generic E.164 shape)   → kept
--   "62..." + on-plan subscriber number                → "+" prepended
--   "0..." + on-plan subscriber number                 → trunk 0 replaced with "62"
--
-- The national trunk 0 is never stripped from a 0-prefixed value that follows
-- the country code, only the one that precedes it: 0620–0628 are real North
-- Sumatra landline area codes (Kabanjahe, Tebing Tinggi, Pematangsiantar, …), so
-- "0628 123 4567" is "+62 628 123 4567" and is handled by the "0..." branch
-- below. Reading it as a stray country code would store "+6281234567", a real
-- mobile number belonging to someone else.
--
-- The Indonesian numbering plan is ^\+62[2-9]\d{7,11}$: subscriber number starts
-- 2-9 and is 8–12 digits (10–14 digits total). Other country codes only need the
-- generic ^\+[1-9]\d{7,14}$ shape. Both patterns are the same strings as
-- phoneIDPattern / phoneGenericPattern in internal/types/parse.go — keep them in
-- sync, or the app will accept values this migration was told to reject.
--
-- Anything else (embedded letters, a bare mobile without the 0/62 prefix, the
-- ambiguous "00" international access prefix, a doubled trunk 0, an Indonesian
-- number off the plan, or a wrong length) is left exactly as typed rather than
-- mangled into something that merely looks valid. Such a value fails the
-- app-side update path, so a member corrects it once through the normal UI.
--
-- One UPDATE, one table scan, both columns from the same pass (see AGENTS.md
-- Rule 8). Rows whose normalized value equals the stored value are not written
-- at all, and NULL stays NULL.

UPDATE users SET whatsapp_number = c.wa, emergency_contact_number = c.ec
FROM (
    SELECT id,
        CASE
            WHEN wa2 ~ '^\+62[2-9][0-9]{7,11}$' THEN wa2
            WHEN wa2 ~ '^\+62'                 THEN wao
            WHEN wa2 ~ '^\+[1-9][0-9]{7,14}$'  THEN wa2
            WHEN wa2 ~ '^62[2-9][0-9]{7,11}$'  THEN '+' || wa2
            WHEN wa2 ~ '^0[2-9][0-9]{7,11}$'   THEN '+62' || substr(wa2, 2)
            ELSE wao
        END AS wa,
        CASE
            WHEN ec2 ~ '^\+62[2-9][0-9]{7,11}$' THEN ec2
            WHEN ec2 ~ '^\+62'                 THEN eco
            WHEN ec2 ~ '^\+[1-9][0-9]{7,14}$'  THEN ec2
            WHEN ec2 ~ '^62[2-9][0-9]{7,11}$'  THEN '+' || ec2
            WHEN ec2 ~ '^0[2-9][0-9]{7,11}$'   THEN '+62' || substr(ec2, 2)
            ELSE eco
        END AS ec
    FROM (
        SELECT id, wao, eco,
            regexp_replace(wa, '^(\+?62)0', '\1') AS wa2,
            regexp_replace(ec, '^(\+?62)0', '\1') AS ec2
        FROM (
            SELECT id,
                whatsapp_number AS wao,
                emergency_contact_number AS eco,
                regexp_replace(coalesce(whatsapp_number, ''), '[ .()\-\u00a0]', '', 'g') AS wa,
                regexp_replace(coalesce(emergency_contact_number, ''), '[ .()\-\u00a0]', '', 'g') AS ec
            FROM users
        ) separators
    ) trunk
) c
WHERE users.id = c.id
  AND (users.whatsapp_number IS DISTINCT FROM c.wa
       OR users.emergency_contact_number IS DISTINCT FROM c.ec);
