package main_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const rootHelp = `Retrieve and cache 1Password Secret Values

Usage:
  secrets [flags]
  secrets [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version

Flags:
  -h, --help      help for secrets
  -v, --version   version for secrets

Use "secrets [command] --help" for more information about a command.
`

type result struct {
	stdout string
	stderr string
	err    error
}

func TestCLIContract(t *testing.T) {
	binary := buildCLI(t, "")
	environment := isolatedEnvironment(t)

	t.Run("plain invocation prints help", func(t *testing.T) {
		got := runCLI(t, binary, environment)

		assertResult(t, got, rootHelp, "", false)
	})

	for _, name := range []string{"unknown", "versions"} {
		t.Run(name+" is a concise usage failure", func(t *testing.T) {
			got := runCLI(t, binary, environment, name)

			wantStderr := fmt.Sprintf("Error: unknown command %q for %q\n", name, "secrets")
			assertResult(t, got, "", wantStderr, true)
		})
	}

	t.Run("invalid argument count is a concise usage failure", func(t *testing.T) {
		got := runCLI(t, binary, environment, "version", "extra")

		assertResult(t, got, "", "Error: accepts 0 arg(s), received 1\n", true)
	})

	for _, args := range [][]string{{"version"}, {"--version"}} {
		name := strings.Join(args, " ")
		t.Run(name+" prints the development version", func(t *testing.T) {
			got := runCLI(t, binary, environment, args...)

			assertResult(t, got, "secrets dev\n", "", false)
		})
	}

	t.Run("does not access user storage or 1Password", func(t *testing.T) {
		got := runCLI(t, binary, environment, "version")
		assertResult(t, got, "secrets dev\n", "", false)

		marker := filepath.Join(environment.fakeBin, "op-invoked")
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("fake op was invoked: %v", err)
		}
		assertDirectoryEmpty(t, environment.home)
		assertDirectoryEmpty(t, environment.cache)
	})
}

func TestBuildInjectedVersion(t *testing.T) {
	binary := buildCLI(t, "1.2.3-test")
	environment := isolatedEnvironment(t)

	for _, args := range [][]string{{"version"}, {"--version"}} {
		name := strings.Join(args, " ")
		t.Run(name, func(t *testing.T) {
			got := runCLI(t, binary, environment, args...)

			assertResult(t, got, "secrets 1.2.3-test\n", "", false)
		})
	}
}

type testEnvironment struct {
	variables []string
	home      string
	cache     string
	fakeBin   string
}

func isolatedEnvironment(t *testing.T) testEnvironment {
	t.Helper()

	root := t.TempDir()
	home := filepath.Join(root, "home")
	cache := filepath.Join(root, "cache")
	fakeBin := filepath.Join(root, "bin")
	for _, directory := range []string{home, cache, fakeBin} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create isolated directory: %v", err)
		}
	}

	marker := filepath.Join(fakeBin, "op-invoked")
	fakeOP := filepath.Join(fakeBin, "op")
	script := fmt.Sprintf("#!/bin/sh\n: > %q\nexit 99\n", marker)
	if err := os.WriteFile(fakeOP, []byte(script), 0o700); err != nil {
		t.Fatalf("create fake op: %v", err)
	}

	variables := make([]string, 0, len(os.Environ())+3)
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if name == "HOME" || name == "USERPROFILE" || name == "XDG_CACHE_HOME" || name == "LOCALAPPDATA" || name == "APPDATA" || name == "PATH" || strings.HasPrefix(name, "OP_") {
			continue
		}
		variables = append(variables, variable)
	}
	variables = append(variables,
		"HOME="+home,
		"USERPROFILE="+home,
		"XDG_CACHE_HOME="+cache,
		"LOCALAPPDATA="+cache,
		"APPDATA="+cache,
		"PATH="+fakeBin,
	)

	return testEnvironment{variables: variables, home: home, cache: cache, fakeBin: fakeBin}
}

func buildCLI(t *testing.T, version string) string {
	t.Helper()

	binary := filepath.Join(t.TempDir(), "secrets")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}

	args := []string{"build", "-o", binary}
	if version != "" {
		args = append(args, "-ldflags", "-X github.com/edsonjaramillo/secrets/internal/commands.Version="+version)
	}
	args = append(args, ".")

	command := exec.Command("go", args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	return binary
}

func runCLI(t *testing.T, binary string, environment testEnvironment, args ...string) result {
	t.Helper()

	command := exec.Command(binary, args...)
	command.Env = environment.variables
	command.Stdin = bytes.NewReader(nil)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()

	return result{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func assertResult(t *testing.T, got result, wantStdout, wantStderr string, wantFailure bool) {
	t.Helper()

	if got.stdout != wantStdout {
		t.Errorf("stdout mismatch\nwant: %q\n got: %q", wantStdout, got.stdout)
	}
	if got.stderr != wantStderr {
		t.Errorf("stderr mismatch\nwant: %q\n got: %q", wantStderr, got.stderr)
	}
	if wantFailure && got.err == nil {
		t.Error("expected nonzero exit status")
	}
	if !wantFailure && got.err != nil {
		t.Errorf("expected successful exit status: %v", got.err)
	}
}

func assertDirectoryEmpty(t *testing.T, path string) {
	t.Helper()

	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read isolated directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected %s to remain empty, found %v", path, entries)
	}
}
