-- Attendance log-in records (prd/attendance.prd). Two-step by design:
--   pending             - the member's own entry, written by POST /v1/attendance
--   confirmed / rejected - an admin's decision (PUT /v1/admin/attendance/:id/...)
-- Location is optional: a member may decline the browser's GPS prompt, in
-- which case latitude/longitude are NULL and the admin sees "no location".
-- The duplicate guard (same member, same dojo, within 10 minutes) lives in
-- the INSERT in internal/attendance/database.go; rejected rows never block
-- a fresh entry.

CREATE TABLE IF NOT EXISTS attendance (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dojo                TEXT NOT NULL,
    instructor          TEXT NOT NULL,
    latitude            DOUBLE PRECISION,
    longitude           DOUBLE PRECISION,
    location_accuracy_m INT,
    logged_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'confirmed', 'rejected')),
    confirmed_by        INT REFERENCES users(id) ON DELETE SET NULL,
    confirmed_at        TIMESTAMPTZ,
    CHECK (latitude IS NULL OR latitude BETWEEN -90 AND 90),
    CHECK (longitude IS NULL OR longitude BETWEEN -180 AND 180),
    -- Coordinates are a pair; a half pair is a client bug, not a location.
    CHECK ((latitude IS NULL) = (longitude IS NULL)),
    CHECK (location_accuracy_m IS NULL OR location_accuracy_m >= 0),
    -- A decision always carries its timestamp; confirmed_by may be NULLed
    -- later by the admin's own account deletion.
    CHECK ((status = 'pending') = (confirmed_at IS NULL))
);

-- Member's own history, newest first (GET /v1/attendance/me).
CREATE INDEX IF NOT EXISTS idx_attendance_user_logged ON attendance(user_id, logged_at DESC);
-- Admin queue by status, newest first (GET /v1/admin/attendance?status=pending).
CREATE INDEX IF NOT EXISTS idx_attendance_status_logged ON attendance(status, logged_at DESC);
-- Admin filter by dojo, newest first.
CREATE INDEX IF NOT EXISTS idx_attendance_dojo_logged ON attendance(dojo, logged_at);
