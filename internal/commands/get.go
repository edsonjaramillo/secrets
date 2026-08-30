package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/edsonjaramillo/secrets/internal/cache"
	"github.com/spf13/cobra"
)

func newGetCommand(dependencies Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:               "get <reference>",
		Short:             "Retrieve a Secret Value",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(command *cobra.Command, args []string) error {
			return runGet(command.Context(), command.OutOrStdout(), dependencies, args[0])
		},
	}
}

func runGet(parent context.Context, stdout io.Writer, dependencies Dependencies, reference string) error {
	if !validSecretReference(reference) {
		return errors.New("invalid Secret Reference")
	}

	ctx, cancel := operationContext(parent, dependencies)
	defer cancel()

	store, err := cache.NewStore()
	if err != nil {
		return cacheFailure(err)
	}
	cachedValue, found, err := store.LookupContext(ctx, reference)
	if err != nil {
		return cacheFailure(err)
	}
	if found {
		_, err = stdout.Write(cachedValue)
		return err
	}
	if err := store.ValidateContext(ctx); err != nil {
		return cacheFailure(err)
	}

	value, err := retrieveSecretValue(ctx, dependencies, reference)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return classifyOnePasswordFailure(ctx, err, "", false)
	}
	if err := store.PutContext(ctx, reference, value, time.Now()); err != nil {
		return cacheFailure(err)
	}
	_, err = stdout.Write(value)
	return err
}

func operationContext(parent context.Context, dependencies Dependencies) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if dependencies.StdinInteractive() {
		return parent, func() {}
	}
	return context.WithTimeout(parent, 5*time.Second)
}

func retrieveSecretValue(ctx context.Context, dependencies Dependencies, reference string) ([]byte, error) {
	path, err := authenticate(ctx, dependencies)
	if err != nil {
		return nil, err
	}
	return readSecretValue(ctx, dependencies, path, reference)
}

func authenticate(ctx context.Context, dependencies Dependencies) (string, error) {
	path, err := exec.LookPath("op")
	if err != nil {
		return "", errors.New("1Password CLI is not installed")
	}

	var probeOutput, probeDiagnostic limitedBuffer
	probe := exec.CommandContext(ctx, path, "whoami")
	probe.Env = environmentWithoutColor(os.Environ())
	probe.Stdin = dependencies.Stdin
	probe.Stdout = &probeOutput
	probe.Stderr = &probeDiagnostic
	if err := probe.Run(); err != nil {
		return "", classifyOnePasswordFailure(ctx, err, probeOutput.String()+"\n"+probeDiagnostic.String(), true)
	}
	return path, nil
}

func readSecretValue(ctx context.Context, dependencies Dependencies, path, reference string) ([]byte, error) {
	var value boundedSecretBuffer
	var diagnostic limitedBuffer
	read := exec.CommandContext(ctx, path, "read", "--no-newline", reference)
	read.Env = environmentWithoutColor(os.Environ())
	read.Stdin = dependencies.Stdin
	read.Stdout = &value
	read.Stderr = &diagnostic
	if err := read.Run(); err != nil {
		return nil, classifyOnePasswordFailure(ctx, err, value.content.String()+"\n"+diagnostic.String(), false)
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyOnePasswordFailure(ctx, err, "", false)
	}
	if value.oversized {
		return nil, errors.New("secret value exceeds the 16 MiB limit")
	}

	return value.content.Bytes(), nil
}

func cacheFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("cache operation timed out")
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("cache operation interrupted")
	}
	if errors.Is(err, cache.ErrEntryNotFound) {
		return errors.New("cache entry not found")
	}
	if errors.Is(err, cache.ErrInvalidState) {
		return errors.New("cache state is invalid; inspect and remove the cache directory manually")
	}
	if errors.Is(err, cache.ErrUnsupportedPlatform) {
		return errors.New("cache security checks are unsupported on this platform")
	}
	return errors.New("cache operation failed")
}

func validSecretReference(reference string) bool {
	if !strings.HasPrefix(reference, "op://") {
		return false
	}
	for _, character := range []byte(reference) {
		if character <= 0x1f || character == 0x7f {
			return false
		}
	}
	return true
}

func classifyOnePasswordFailure(ctx context.Context, err error, diagnostic string, authenticationProbe bool) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("1Password request timed out")
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.New("1Password request interrupted")
	}
	if authenticationRequired(diagnostic) {
		return errors.New("authentication required; run `op signin` or enable 1Password desktop-app CLI integration")
	}
	if !authenticationProbe && invalidOrMissingReference(diagnostic) {
		return errors.New("secret reference is invalid or not found")
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return fmt.Errorf("1Password command failed with exit code %d", exitError.ExitCode())
	}
	return errors.New("1Password command failed")
}

func invalidOrMissingReference(diagnostic string) bool {
	message := strings.ToLower(diagnostic)
	for _, phrase := range []string{
		"invalid secret reference",
		"invalid reference",
		"not found",
		"doesn't exist",
		"does not exist",
	} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

type boundedSecretBuffer struct {
	content   bytes.Buffer
	oversized bool
}

func (buffer *boundedSecretBuffer) Write(content []byte) (int, error) {
	originalLength := len(content)
	remaining := cache.MaximumSecretValueSize - buffer.content.Len()
	if len(content) > remaining {
		buffer.oversized = true
		content = content[:remaining]
	}
	if len(content) > 0 {
		_, _ = buffer.content.Write(content)
	}
	return originalLength, nil
}
