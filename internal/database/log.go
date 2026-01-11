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
	duration := time.Since(event.StartTime)
	if event.Err != nil {
		log.Error().Caller().Err(event.Err).Dur("duration", duration).Msg(event.Query)
		return
	}

	log.Debug().Caller().Dur("duration", duration).Msg(event.Query)

}
