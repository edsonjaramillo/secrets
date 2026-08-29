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

	"github.com/spf13/cobra"
)

const authenticationGuidance = "Authentication required: run `op signin` or enable 1Password desktop-app CLI integration.\n"

var errStatusNotReady = errors.New("1Password is not ready")

func newStatusCommand(dependencies Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report 1Password readiness",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runStatus(command.Context(), command.OutOrStdout(), command.ErrOrStderr(), dependencies)
		},
	}
}

func runStatus(parent context.Context, stdout, stderr io.Writer, dependencies Dependencies) error {
	ctx := parent
	cancel := func() {}
	if !dependencies.StdinInteractive() {
		ctx, cancel = context.WithTimeout(parent, 5*time.Second)
	}
	defer cancel()

	path, err := exec.LookPath("op")
	if err != nil {
		_, writeErr := io.WriteString(stdout, "op: missing\nauthentication: unavailable\n")
		if writeErr != nil {
			return writeErr
		}
		return errStatusNotReady
	}

	var output, diagnostic limitedBuffer
	probe := exec.CommandContext(ctx, path, "whoami")
	probe.Env = environmentWithoutColor(os.Environ())
	probe.Stdin = dependencies.Stdin
	probe.Stdout = &output
	probe.Stderr = &diagnostic
	err = probe.Run()

	state := "ready"
	if err != nil {
		state = "error"
		if authenticationRequired(output.String() + "\n" + diagnostic.String()) {
			state = "required"
		}
	}

	if _, writeErr := fmt.Fprintf(stdout, "op: installed\nauthentication: %s\n", state); writeErr != nil {
		return writeErr
	}
	if state == "required" {
		if _, writeErr := io.WriteString(stderr, authenticationGuidance); writeErr != nil {
			return writeErr
		}
	}
	if state != "ready" {
		return errStatusNotReady
	}
	return nil
}

func environmentWithoutColor(environment []string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, variable := range environment {
		if name, _, _ := strings.Cut(variable, "="); name != "NO_COLOR" {
			result = append(result, variable)
		}
	}
	return append(result, "NO_COLOR=1")
}

func authenticationRequired(diagnostic string) bool {
	message := strings.ToLower(diagnostic)
	for _, phrase := range []string{
		"not currently signed in",
		"not signed in",
		"authentication required",
		"authorization required",
		"op signin",
	} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

// limitedBuffer bounds untrusted diagnostics used only for classification.
type limitedBuffer struct {
	content bytes.Buffer
}

func (buffer *limitedBuffer) String() string {
	return buffer.content.String()
}

func (buffer *limitedBuffer) Write(content []byte) (int, error) {
	const limit = 64 * 1024
	originalLength := len(content)
	remaining := limit - buffer.content.Len()
	if remaining > 0 {
		if len(content) > remaining {
			content = content[:remaining]
		}
		_, _ = buffer.content.Write(content)
	}
	return originalLength, nil
}
