package commands

import (
	"fmt"
	"io"

	"github.com/edsonjaramillo/secrets/internal/cache"
	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "cache",
		Short: "Manage Cache Entries",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(newCacheListCommand())
	return command
}

func newCacheListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Cache Entries in a human-readable format",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runCacheList(command.OutOrStdout())
		},
	}
}

func runCacheList(stdout io.Writer) error {
	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	entries, err := store.List()
	if err != nil {
		return cacheFailure(err)
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\n", entry.CachedAt, entry.Reference); err != nil {
			return err
		}
	}
	return nil
}
