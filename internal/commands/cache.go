package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/edsonjaramillo/secrets/internal/cache"
	"github.com/spf13/cobra"
)

func newCacheCommand(dependencies Dependencies) *cobra.Command {
	command := &cobra.Command{
		Use:   "cache",
		Short: "Manage Cache Entries",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(newCacheListCommand(), newCacheClearCommand(), newCacheRevalidateCommand(dependencies))
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

func newCacheClearCommand() *cobra.Command {
	var all bool
	command := &cobra.Command{
		Use:   "clear [reference]",
		Short: "Logically remove Cache Entries",
		Long:  "Logically remove one Cache Entry or all Cache Entries. This does not guarantee secure erasure from storage media, journals, snapshots, or backups.",
		Args: func(_ *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return errors.New("accepts either one Secret Reference or --all")
				}
				return nil
			}
			if len(args) != 1 {
				return errors.New("requires exactly one Secret Reference or --all")
			}
			if !validSecretReference(args[0]) {
				return errors.New("invalid Secret Reference")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			return runCacheClear(args, all)
		},
	}
	command.Flags().BoolVar(&all, "all", false, "Remove all Cache Entries")
	return command
}

func newCacheRevalidateCommand(dependencies Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "revalidate <reference>",
		Short: "Replace one existing Cache Entry",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("requires exactly one Secret Reference")
			}
			if !validSecretReference(args[0]) {
				return errors.New("invalid Secret Reference")
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			return runCacheRevalidate(command.Context(), dependencies, args[0])
		},
	}
}

func runCacheRevalidate(parent context.Context, dependencies Dependencies, reference string) error {
	if !validSecretReference(reference) {
		return errors.New("invalid Secret Reference")
	}

	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	found, err := store.ValidateEntry(reference)
	if err != nil {
		return cacheFailure(err)
	}
	if !found {
		return cacheFailure(cache.ErrEntryNotFound)
	}

	ctx, cancel := onePasswordContext(parent, dependencies)
	defer cancel()
	value, err := retrieveSecretValue(ctx, dependencies, reference)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return classifyOnePasswordFailure(ctx, err, "", false)
	}
	if err := store.Revalidate(reference, value, time.Now()); err != nil {
		return cacheFailure(err)
	}
	return nil
}

func runCacheClear(args []string, all bool) error {
	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	if all {
		err = store.ClearAll()
	} else {
		err = store.Clear(args[0])
	}
	if err != nil {
		return cacheFailure(err)
	}
	return nil
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
