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
	"time"

	"github.com/creack/pty"
)

const rootHelp = `Retrieve and cache 1Password Secret Values

Usage:
  secrets [flags]
  secrets [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  status      Report 1Password readiness
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

func TestStatus(t *testing.T) {
	binary := buildCLI(t, "")

	t.Run("authenticated context is ready", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables,
			"FAKE_OP_MODE=ready",
			"OP_ACCOUNT=work",
			"OP_SESSION_work=session-value",
		)

		got := runCLI(t, binary, environment, "status")

		assertResult(t, got, "op: installed\nauthentication: ready\n", "", false)
		invocation := readInvocation(t, environment)
		if invocation != "whoami|work|session-value|1\n" {
			t.Errorf("unexpected op invocation: %q", invocation)
		}
	})

	t.Run("missing CLI is unavailable", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		if err := os.Remove(filepath.Join(environment.fakeBin, "op")); err != nil {
			t.Fatalf("remove fake op: %v", err)
		}

		got := runCLI(t, binary, environment, "status")

		assertResult(t, got, "op: missing\nauthentication: unavailable\n", "", true)
	})

	t.Run("signed out context requires authentication", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=required")

		got := runCLI(t, binary, environment, "status")

		assertResult(t, got, "op: installed\nauthentication: required\n", "Authentication required: run `op signin` or enable 1Password desktop-app CLI integration.\n", true)
	})

	t.Run("authentication diagnostic on stdout remains private", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=required-stdout")

		got := runCLI(t, binary, environment, "status")

		assertResult(t, got, "op: installed\nauthentication: required\n", "Authentication required: run `op signin` or enable 1Password desktop-app CLI integration.\n", true)
	})

	t.Run("interactive probe receives stdin", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=interactive")

		got := runCLIWithTerminal(t, binary, environment, "approved\n", false)

		assertResult(t, got, "op: installed\nauthentication: ready\n", "", false)
	})

	t.Run("interactive probe is cancellable", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=hang")
		started := time.Now()

		got := runCLIWithTerminal(t, binary, environment, "", true)

		assertResult(t, got, "op: installed\nauthentication: error\n", "", true)
		if elapsed := time.Since(started); elapsed > 4*time.Second {
			t.Errorf("interactive cancellation took %s", elapsed)
		}
	})

	t.Run("unexpected probe failure is controlled", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=error")

		got := runCLI(t, binary, environment, "status")

		assertResult(t, got, "op: installed\nauthentication: error\n", "", true)
		if strings.Contains(got.stdout+got.stderr, "account@example.com") || strings.Contains(got.stdout+got.stderr, "raw diagnostic") {
			t.Error("status forwarded raw op output")
		}
	})

	t.Run("non-interactive probe has one five second deadline", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=hang")
		started := time.Now()

		got := runCLI(t, binary, environment, "status")
		elapsed := time.Since(started)

		assertResult(t, got, "op: installed\nauthentication: error\n", "", true)
		if elapsed < 4*time.Second || elapsed > 8*time.Second {
			t.Errorf("expected a five second deadline, elapsed %s", elapsed)
		}
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
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s|%%s|%%s|%%s\n' "$*" "$OP_ACCOUNT" "$OP_SESSION_work" "$NO_COLOR" > %q
case "$FAKE_OP_MODE" in
  ready)
    echo 'account@example.com'
    echo 'raw diagnostic' >&2
    exit 0
    ;;
  required)
    echo 'account@example.com'
    echo 'You are not currently signed in. raw diagnostic' >&2
    exit 1
    ;;
  required-stdout)
    echo 'You are not currently signed in. account@example.com'
    echo 'raw diagnostic' >&2
    exit 1
    ;;
  interactive)
    IFS= read -r answer
    test "$answer" = approved
    ;;
  error)
    echo 'account@example.com'
    echo 'raw diagnostic' >&2
    exit 7
    ;;
  hang)
    while :; do :; done
    ;;
  *) exit 99 ;;
esac
`, marker)
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

func runCLIWithTerminal(t *testing.T, binary string, environment testEnvironment, input string, cancel bool) result {
	t.Helper()

	terminal, childTerminal, err := pty.Open()
	if err != nil {
		t.Fatalf("open terminal: %v", err)
	}
	defer func() { _ = terminal.Close() }()
	defer func() { _ = childTerminal.Close() }()

	command := exec.Command(binary, "status")
	command.Env = environment.variables
	command.Stdin = childTerminal
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start CLI: %v", err)
	}

	if input != "" {
		if _, err := terminal.WriteString(input); err != nil {
			t.Fatalf("write terminal input: %v", err)
		}
	}
	if cancel {
		marker := filepath.Join(environment.fakeBin, "op-invoked")
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := os.Stat(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				_ = command.Process.Kill()
				t.Fatal("fake op was not invoked")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := command.Process.Signal(os.Interrupt); err != nil {
			t.Fatalf("interrupt CLI: %v", err)
		}
	}

	err = command.Wait()
	return result{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func readInvocation(t *testing.T, environment testEnvironment) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(environment.fakeBin, "op-invoked"))
	if err != nil {
		t.Fatalf("read fake op invocation: %v", err)
	}

	return string(content)
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
