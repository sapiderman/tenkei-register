-- User categories (regular / student / kids) — new-category.prd.
-- The category rule is enforced in application code (types.
-- CategoryFieldsMissing); faculty/major stay as-is and are only relabelled
-- Department/Major at the API surface.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS category      TEXT NOT NULL DEFAULT 'regular',
    ADD COLUMN IF NOT EXISTS university    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS school_name   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS guardian_name TEXT NOT NULL DEFAULT '';

-- Backfill: UI-campus members that already carry faculty+major are students.
-- The dojo was the implicit university signal before categories existed.
-- Idempotent and data-safe: everyone else keeps the 'regular' default.
UPDATE users
SET category = 'student',
    university = 'Universitas Indonesia'
WHERE dojo = 'Tenkei Universitas Indonesia'
  AND faculty <> '' AND major <> '';
