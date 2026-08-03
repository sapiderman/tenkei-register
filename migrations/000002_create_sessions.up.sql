CREATE TABLE IF NOT EXISTS sessions (
    id          VARCHAR(64) PRIMARY KEY,
    user_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMPTZ NOT NULL,
    verified    BOOLEAN NOT NULL DEFAULT TRUE
);

-- Idempotent index creation
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);