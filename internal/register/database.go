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

// dbGetUserByEmail retrieves a user by their email address.
// Returns nil if no user is found.
func (r *registrar) dbGetUserByEmail(ctx context.Context, email string) (*User, error) {
	user := new(User)
	err := r.db.NewSelect().Model(user).Where("email = ?", email).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// dbGetUserByWhatsApp retrieves a user by their WhatsApp number.
// Returns nil if no user is found.
func (r *registrar) dbGetUserByWhatsApp(ctx context.Context, whatsapp string) (*User, error) {
	user := new(User)
	err := r.db.NewSelect().Model(user).Where("whatsapp_number = ?", whatsapp).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// dbCountUsers returns the total number of registered users.
func (r *registrar) dbCountUsers(ctx context.Context) (int, error) {
	count, err := r.db.NewSelect().Model((*User)(nil)).Count(ctx)
	if err != nil {
		return 0, err
	}
	return count, nil
}
