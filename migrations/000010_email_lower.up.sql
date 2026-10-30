-- Make email a case-insensitive identifier (audit-fix-plan PR-5-emailcase).
-- Two rules land together: application writes store emails lowercase, and
-- every lookup matches on lower(email) (BcryptVerifier.findUserByEmail,
-- DBPasswordResetter.RequestReset, ApplyProfileUpdate's conflict count).
-- This migration moves the stored data to the same rule so the two spellings
-- of one address are one account.
--
-- Step 1 is the abort guard. If two rows differ only by email case, step 2
-- would collapse them into one row (one account silently absorbs the other's
-- login) and step 3's unique index would fail half-built. Postgres raises
-- instead, naming every duplicated address so an operator resolves them out
-- of band and re-runs. Preflight the same condition read-only before deploy:
--   SELECT lower(email), count(*) FROM users
--   GROUP BY lower(email) HAVING count(*) > 1;
--
-- Step 2 rewrites only rows that differ (IS DISTINCT FROM), so an
-- already-clean database is a no-op write, and lower() of an already
-- lowercase value is exact — no length or collation surprises (Rule 8).
--
-- Step 3 swaps the raw-column unique index for a functional one on
-- lower(email). Uniqueness is then enforced case-insensitively at the DB, so
-- out-of-band mixed-case writes collide instead of splitting an account into
-- two spellings. ON CONFLICT (email) inference targets no longer match this
-- index — only the test seed helper used one, updated in the same PR.

DO $$
DECLARE
    dupes text;
BEGIN
    SELECT string_agg(email, ', ' ORDER BY email)
      INTO dupes
      FROM (
          SELECT lower(email) AS email
            FROM users
           GROUP BY lower(email)
          HAVING count(*) > 1
      ) d;

    IF dupes IS NOT NULL THEN
        RAISE EXCEPTION 'case-insensitive email migration aborted: addresses held by more than one row: %', dupes;
    END IF;
END
$$;

UPDATE users SET email = lower(email) WHERE email IS DISTINCT FROM lower(email);

DROP INDEX users_email_idx;
CREATE UNIQUE INDEX users_email_lower_idx ON users USING btree (lower(email));
