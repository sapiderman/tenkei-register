package register

import (
	"context"
)

// dbInsertUser inserts a new user record into the database.
// Uses bun ORM for type-safe insertion with the User model.
func (r *registrar) dbInsertUser(ctx context.Context, user *User) error {
	_, err := r.db.NewInsert().Model(user).Exec(ctx)
	return err
}
