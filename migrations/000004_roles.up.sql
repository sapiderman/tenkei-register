-- User roles & authorization foundation (PRD: User Roles & Administration).
-- Four roles with numeric levels: new=0, user=1, admin=2, superuser=3.
--
-- 1) Backfill every legacy row to the verified 'user' role in one statement
--    that provably preserves any genuine admin/superuser (and any already
--    'new'/'user'). Only NULL/empty/garbage values are rewritten.
-- 2) Make role NOT NULL, default new registrations to 'new' (the pending
--    state — register.go already hard-codes 'new'), and constrain to the
--    four valid values via a CHECK.
UPDATE users
   SET role = 'user'
 WHERE role IS NULL
    OR role = ''
    OR role NOT IN ('new', 'user', 'admin', 'superuser');

ALTER TABLE users ALTER COLUMN role SET NOT NULL;
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'new';

ALTER TABLE users
    ADD CONSTRAINT users_role_check
    CHECK (role IN ('new', 'user', 'admin', 'superuser'));
