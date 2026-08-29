package commands

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Version is the build version. Release builds replace it with -ldflags -X.
var Version = "dev"

// Dependencies contains the process resources used by commands.
type Dependencies struct {
	Context context.Context
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// StdinInteractive reports whether authentication may interact with the user.
func (dependencies Dependencies) StdinInteractive() bool {
	file, ok := dependencies.Stdin.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(file.Fd()))
}

// NewRoot constructs an independently executable command tree.
func NewRoot(dependencies Dependencies) *cobra.Command {
	root := &cobra.Command{
		Use:                "secrets",
		Short:              "Retrieve and cache 1Password Secret Values",
		Version:            Version,
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableSuggestions: true,
		Args:               cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetIn(dependencies.Stdin)
	root.SetOut(dependencies.Stdout)
	root.SetErr(dependencies.Stderr)
	root.SetVersionTemplate("secrets {{.Version}}\n")
	root.AddCommand(newStatusCommand(dependencies), newVersionCommand())

	return root
}

// Run executes the command tree and translates a command error to a process status.
func Run(dependencies Dependencies) int {
	ctx := dependencies.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := NewRoot(dependencies).ExecuteContext(ctx); err != nil {
		if !errors.Is(err, errStatusNotReady) {
			_, _ = fmt.Fprintf(dependencies.Stderr, "Error: %v\n", err)
		}

		return 1
	}

	return 0
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.ExactArgs(0),
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(command.OutOrStdout(), "secrets %s\n", Version)

			return err
		},
	}
}
