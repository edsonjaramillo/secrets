package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
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
	var all bool
	command := &cobra.Command{
		Use:   "revalidate [reference]",
		Short: "Replace existing Cache Entries",
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
		RunE: func(command *cobra.Command, args []string) error {
			if all {
				return runCacheRevalidateAll(command.Context(), dependencies)
			}
			return runCacheRevalidate(command.Context(), dependencies, args[0])
		},
	}
	command.Flags().BoolVar(&all, "all", false, "Replace all Cache Entries")
	return command
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

type bulkRevalidationFailure struct {
	identifier string
	reason     string
}

type bulkRevalidationError struct {
	failures []bulkRevalidationFailure
}

func (err bulkRevalidationError) Error() string {
	lines := make([]string, 0, len(err.failures)+1)
	for _, failure := range err.failures {
		lines = append(lines, fmt.Sprintf("cache entry %s failed to revalidate: %s", failure.identifier, failure.reason))
	}
	lines = append(lines, bulkRevalidationSummary(len(err.failures)))
	return strings.Join(lines, "\n")
}

func bulkRevalidationSummary(failures int) string {
	if failures == 1 {
		return "1 cache entry failed to revalidate"
	}
	return fmt.Sprintf("%d cache entries failed to revalidate", failures)
}

func runCacheRevalidateAll(parent context.Context, dependencies Dependencies) error {
	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	entries, err := store.List()
	if err != nil {
		return cacheFailure(err)
	}
	if len(entries) == 0 {
		return nil
	}

	ctx, cancel := onePasswordContext(parent, dependencies)
	defer cancel()

	path, err := authenticate(ctx, dependencies)
	if err != nil {
		return allBulkRevalidationFailures(entries, err)
	}

	failures := make([]bulkRevalidationFailure, 0)
	for index, item := range entries {
		if ctx.Err() != nil {
			failures = appendBulkCancellationFailures(failures, entries, index, ctx)
			break
		}

		value, retrieveErr := readSecretValue(ctx, dependencies, path, item.Reference)
		if retrieveErr != nil {
			if ctx.Err() != nil {
				retrieveErr = contextFailure(ctx)
			}
			failures = append(failures, bulkRevalidationFailure{
				identifier: cache.Identifier(item.Reference),
				reason:     retrieveErr.Error(),
			})
			if ctx.Err() != nil {
				failures = appendBulkCancellationFailures(failures, entries, index+1, ctx)
				break
			}
			continue
		}
		if ctx.Err() != nil {
			failures = append(failures, bulkRevalidationFailure{
				identifier: cache.Identifier(item.Reference),
				reason:     contextFailure(ctx).Error(),
			})
			failures = appendBulkCancellationFailures(failures, entries, index+1, ctx)
			break
		}

		if commitErr := store.Revalidate(item.Reference, value, time.Now()); commitErr != nil {
			failures = append(failures, bulkRevalidationFailure{
				identifier: cache.Identifier(item.Reference),
				reason:     cacheFailure(commitErr).Error(),
			})
			if ctx.Err() != nil {
				failures = appendBulkCancellationFailures(failures, entries, index+1, ctx)
				break
			}
		}
	}

	if len(failures) > 0 {
		return bulkRevalidationError{failures: failures}
	}
	return nil
}

func allBulkRevalidationFailures(entries []cache.ListingEntry, err error) error {
	failures := appendBulkRevalidationFailures(nil, entries, err.Error())
	return bulkRevalidationError{failures: failures}
}

func appendBulkCancellationFailures(failures []bulkRevalidationFailure, entries []cache.ListingEntry, start int, ctx context.Context) []bulkRevalidationFailure {
	return appendBulkRevalidationFailures(failures, entries[start:], contextFailure(ctx).Error())
}

func appendBulkRevalidationFailures(failures []bulkRevalidationFailure, entries []cache.ListingEntry, reason string) []bulkRevalidationFailure {
	for _, item := range entries {
		failures = append(failures, bulkRevalidationFailure{
			identifier: cache.Identifier(item.Reference),
			reason:     reason,
		})
	}
	return failures
}

func contextFailure(ctx context.Context) error {
	return classifyOnePasswordFailure(ctx, ctx.Err(), "", false)
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
