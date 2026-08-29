package main

import (
	"os"

	"github.com/edsonjaramillo/secrets/internal/commands"
)

func main() {
	os.Exit(commands.Run(commands.Dependencies{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}))
}
