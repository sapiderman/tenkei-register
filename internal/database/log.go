package database

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
)

type queryHook struct{}

func (h *queryHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

func (h *queryHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	dur := time.Since(event.StartTime)
	if event.Err != nil {
		log.Error().Err(event.Err).Dur("duration", dur).Msg(event.Query)
		return
	}

	log.Debug().Dur("duration", dur).Msg(event.Query)
}
