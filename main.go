// Package main is the starting point
package main

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal"
)

func main() {

	log.Info().Msg("Application started")
	internal.StartServer(context.Background())
}
