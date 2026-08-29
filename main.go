package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/edsonjaramillo/secrets/internal/commands"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	os.Exit(commands.Run(commands.Dependencies{
		Context: ctx,
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}))
}
