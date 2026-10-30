package database

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/driver/pgdriver"
)

type queryHook struct{}

func (h *queryHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

func (h *queryHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	duration := time.Since(event.StartTime)
	if event.Err != nil {
		var pgErr pgdriver.Error
		if errors.As(event.Err, &pgErr) {
			// Postgres messages embed member values (e.g. the duplicate email
			// in a unique-violation detail); only the SQLSTATE is safe to log.
			log.Error().Caller().Str("sqlstate", pgErr.Field('C')).Dur("duration", duration).Msg(event.Operation())
			return
		}
		// Non-pgdriver errors are transport/infra failures, no member data.
		log.Error().Caller().Err(event.Err).Dur("duration", duration).Msg(event.Operation())
		return
	}

	log.Debug().Caller().Dur("duration", duration).Msg(event.Operation())
}
