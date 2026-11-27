-- Instructor roster per dojo, the picklist for the attendance dialog
-- (GET /v1/attendance/instructors). Rarely changes: add or remove rows by
-- hand rather than shipping a deploy, e.g.
--   INSERT INTO instructors (dojo, name) VALUES ('Tenkei Mayapada', 'Sensei Name');
--   DELETE FROM instructors WHERE dojo = 'Tenkei Mayapada' AND name = 'Sensei Name';
-- A row with dojo '' (empty string, never NULL) means the instructor teaches
-- at every dojo:   INSERT INTO instructors (dojo, name) VALUES ('', 'Sensei Name');
-- attendance.instructor stays plain text on purpose: a log is a historical
-- record and must survive a rename or removal here.

CREATE TABLE IF NOT EXISTS instructors (
    id         BIGSERIAL PRIMARY KEY,
    dojo       TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (dojo, name)
);

-- Seed: one row per instructor per dojo, plus '' rows for everyone who
-- teaches everywhere. A dojo with neither shows "no instructors listed yet"
-- in the member dialog until it is added.
-- INSERT INTO instructors (dojo, name) VALUES
--     ('', '…'),
--     ('Tenkei Mayapada', '…');
