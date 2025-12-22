// Package database provides database interaction functionalities
package database

import (
	"database/sql"

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
	db.AddQueryHook(&queryHook{})
	if err := db.Ping(); err != nil {
		log.Fatal().Err(err).Msg("failed to ping database")
		return nil, err
	}

	return &Database{DB: db}, nil
}

func (db *Database) Close() error {
	return db.DB.Close()
}

func (db *Database) GetDB() *bun.DB {
	return db.DB
}
