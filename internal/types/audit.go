package types

import (
	"time"

	"github.com/uptrace/bun"
)

// Audit is the shared database model for the audit table.
type Audit struct {
	bun.BaseModel `bun:"table:audit"`

	ID        int64     `bun:"id,pk,autoincrement"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp"`
	UserID    int64     `bun:"user_id"`
	Action    string    `bun:"action"`
}
