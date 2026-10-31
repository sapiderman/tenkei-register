// Package database provides database interaction functionalities
package database

import (
	"database/sql"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

type Database struct {
	DB *bun.DB
}

func New(dsn string) (*Database, error) {
	db := bun.NewDB(sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn))), pgdialect.New())
	// WithQueryHook clones the DB and hooks the clone; the receiver is
	// returned unmodified, so the return value must be captured.
	db = db.WithQueryHook(&queryHook{})
	if err := db.Ping(); err != nil {
		log.Error().Caller().Err(err).Msg("failed to ping database")
		return nil, err
	}
	log.Info().Caller().Msg("db OK: db ponged when pinged.")

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &Database{DB: db}, nil
}

func (db *Database) Close() error {
	return db.DB.Close()
}

func (db *Database) GetDB() *bun.DB {
	return db.DB
}
