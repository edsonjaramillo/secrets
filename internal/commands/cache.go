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
	command.AddCommand(newCacheListCommand(dependencies), newCacheClearCommand(dependencies), newCacheRevalidateCommand(dependencies))
	return command
}

func newCacheListCommand(dependencies Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Cache Entries in a human-readable format",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runCacheList(command.Context(), dependencies, command.OutOrStdout())
		},
	}
}

func newCacheClearCommand(dependencies Dependencies) *cobra.Command {
	var all bool
	command := &cobra.Command{
		Use:               "clear [reference]",
		Short:             "Logically remove Cache Entries",
		Long:              "Logically remove one Cache Entry or all Cache Entries. This does not guarantee secure erasure from storage media, journals, snapshots, or backups.",
		ValidArgsFunction: completeCachedSecretReferences(dependencies),
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
			return runCacheClear(command.Context(), dependencies, args, all)
		},
	}
	command.Flags().BoolVar(&all, "all", false, "Remove all Cache Entries")
	return command
}

func newCacheRevalidateCommand(dependencies Dependencies) *cobra.Command {
	var all bool
	command := &cobra.Command{
		Use:               "revalidate [reference]",
		Short:             "Replace existing Cache Entries",
		ValidArgsFunction: completeCachedSecretReferences(dependencies),
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

func completeCachedSecretReferences(dependencies Dependencies) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(command *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		const noFileCompletion = cobra.ShellCompDirectiveNoFileComp
		if len(args) != 0 || command.Flags().Changed("all") {
			return nil, noFileCompletion
		}

		ctx, cancel := operationContext(command.Context(), dependencies)
		defer cancel()

		store, err := cache.NewStore()
		if err != nil {
			return nil, noFileCompletion
		}
		entries, err := store.ListContext(ctx)
		if err != nil {
			return nil, noFileCompletion
		}

		completions := make([]string, 0, len(entries))
		for _, entry := range entries {
			if strings.HasPrefix(entry.Reference, toComplete) {
				completions = append(completions, entry.Reference)
			}
		}
		return completions, noFileCompletion
	}
}

func runCacheRevalidate(parent context.Context, dependencies Dependencies, reference string) error {
	if !validSecretReference(reference) {
		return errors.New("invalid Secret Reference")
	}

	ctx, cancel := operationContext(parent, dependencies)
	defer cancel()

	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	found, err := store.ValidateEntryContext(ctx, reference)
	if err != nil {
		return cacheFailure(err)
	}
	if !found {
		return cacheFailure(cache.ErrEntryNotFound)
	}

	value, err := retrieveSecretValue(ctx, dependencies, reference)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return classifyOnePasswordFailure(ctx, err, "", false)
	}
	if err := store.RevalidateContext(ctx, reference, value, time.Now()); err != nil {
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
	ctx, cancel := operationContext(parent, dependencies)
	defer cancel()

	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	entries, err := store.ListContext(ctx)
	if err != nil {
		return cacheFailure(err)
	}
	if len(entries) == 0 {
		return nil
	}

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

		if commitErr := store.RevalidateContext(ctx, item.Reference, value, time.Now()); commitErr != nil {
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

func runCacheClear(parent context.Context, dependencies Dependencies, args []string, all bool) error {
	ctx, cancel := operationContext(parent, dependencies)
	defer cancel()

	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	if all {
		err = store.ClearAllContext(ctx)
	} else {
		err = store.ClearContext(ctx, args[0])
	}
	if err != nil {
		return cacheFailure(err)
	}
	return nil
}

func runCacheList(parent context.Context, dependencies Dependencies, stdout io.Writer) error {
	ctx, cancel := operationContext(parent, dependencies)
	defer cancel()

	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	entries, err := store.ListContext(ctx)
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
