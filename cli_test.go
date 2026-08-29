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
  get         Retrieve a Secret Value
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

func TestGet(t *testing.T) {
	binary := buildCLI(t, "")

	t.Run("requires exactly one Secret Reference and accepts no flags", func(t *testing.T) {
		for caseIndex, args := range [][]string{
			{"get"},
			{"get", "op://one", "op://two"},
			{"get", "--all", "op://one"},
		} {
			environment := isolatedEnvironment(t)
			got := runCLI(t, binary, environment, args...)
			if got.err == nil || got.stdout != "" || !strings.HasPrefix(got.stderr, "Error: ") {
				t.Errorf("usage case %d was not a concise failure", caseIndex)
			}
			assertNotInvoked(t, environment)
		}
	})

	t.Run("rejects invalid local Secret References without invoking 1Password", func(t *testing.T) {
		for _, secretReference := range []string{"", "vault/item/field", "op://vault/item/\x01field", "op://vault/item/\nfield", "op://vault/item/\x7ffield"} {
			environment := isolatedEnvironment(t)
			got := runCLI(t, binary, environment, "get", secretReference)
			assertControlledGetFailure(t, got, "Error: invalid Secret Reference\n")
			assertNotInvoked(t, environment)
		}
	})

	t.Run("delegates spaces Unicode and full syntax validation to op", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		secretReference := "op://My Vault/日本語 item/field?attribute=otp"

		got := runCLI(t, binary, environment, "get", secretReference)

		assertSecretResult(t, got, []byte("opaque value\nwith trailing newline\n"))
		if invocations := readInvocation(t, environment); !strings.Contains(invocations, "read --no-newline "+secretReference+"|||") {
			t.Error("Secret Reference was not delegated exactly")
		}
	})

	t.Run("retrieves exact Secret Value bytes after authentication", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables,
			"FAKE_OP_MODE=get-exact",
			"OP_ACCOUNT=work",
			"OP_SESSION_work=session-value",
		)

		got := runCLI(t, binary, environment, "get", "op://vault/item/field")

		assertSecretResult(t, got, []byte("opaque value\nwith trailing newline\n"))
		invocations := readInvocation(t, environment)
		if invocations != "whoami|work|session-value|1\nread --no-newline op://vault/item/field|work|session-value|1\n" {
			t.Error("unexpected op invocations")
		}
	})

	for _, test := range []struct {
		name string
		mode string
		want []byte
	}{
		{name: "empty", mode: "get-empty", want: []byte{}},
		{name: "non UTF-8", mode: "get-binary", want: []byte{0xff, 0x00, 'A', '\n'}},
	} {
		t.Run(test.name+" Secret Value is emitted byte-for-byte", func(t *testing.T) {
			environment := isolatedEnvironment(t)
			environment.variables = append(environment.variables, "FAKE_OP_MODE="+test.mode)

			got := runCLI(t, binary, environment, "get", "op://vault/item/field")

			assertSecretResult(t, got, test.want)
		})
	}

	t.Run("accepts exactly 16 MiB", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-limit")

		got := runCLI(t, binary, environment, "get", "op://vault/item/field")

		if got.err != nil || got.stderr != "" || len(got.stdout) != 16*1024*1024 || strings.Trim(got.stdout, "\x00") != "" {
			t.Errorf("16 MiB boundary failed (stdout length %d, stderr length %d, failed %t)", len(got.stdout), len(got.stderr), got.err != nil)
		}
	})

	t.Run("rejects oversized and partial output", func(t *testing.T) {
		for _, mode := range []string{"get-oversized", "get-partial-failure"} {
			environment := isolatedEnvironment(t)
			environment.variables = append(environment.variables, "FAKE_OP_MODE="+mode)

			got := runCLI(t, binary, environment, "get", "op://vault/private-item/field")

			if got.err == nil || got.stdout != "" {
				t.Errorf("%s did not fail with empty stdout (stdout length %d)", mode, len(got.stdout))
			}
			for _, forbiddenContent := range []string{"partial Secret Value", "arbitrary subprocess diagnostic", "op://vault/private-item/field"} {
				if strings.Contains(got.stderr, forbiddenContent) {
					t.Errorf("%s leaked private subprocess content", mode)
				}
			}
		}
	})

	t.Run("controlled subprocess failures do not disclose private content", func(t *testing.T) {
		for _, test := range []struct {
			mode, want string
		}{
			{mode: "get-auth-required", want: "Error: authentication required; run `op signin` or enable 1Password desktop-app CLI integration\n"},
			{mode: "get-auth-read-stdout", want: "Error: authentication required; run `op signin` or enable 1Password desktop-app CLI integration\n"},
			{mode: "get-invalid", want: "Error: secret reference is invalid or not found\n"},
			{mode: "get-invalid-stdout", want: "Error: secret reference is invalid or not found\n"},
			{mode: "get-not-found", want: "Error: secret reference is invalid or not found\n"},
			{mode: "get-unknown", want: "Error: 1Password command failed with exit code 23\n"},
		} {
			environment := isolatedEnvironment(t)
			environment.variables = append(environment.variables, "FAKE_OP_MODE="+test.mode)
			secretReference := "op://vault/private-item/field"

			got := runCLI(t, binary, environment, "get", secretReference)

			assertControlledGetFailure(t, got, test.want)
			for _, forbiddenContent := range []string{"partial Secret Value", "arbitrary subprocess diagnostic", secretReference} {
				if strings.Contains(got.stdout+got.stderr, forbiddenContent) {
					t.Errorf("%s leaked private subprocess content", test.mode)
				}
			}
		}
	})

	t.Run("missing CLI is controlled", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		if err := os.Remove(filepath.Join(environment.fakeBin, "op")); err != nil {
			t.Fatalf("remove fake op: %v", err)
		}

		got := runCLI(t, binary, environment, "get", "op://vault/private-item/field")

		assertControlledGetFailure(t, got, "Error: 1Password CLI is not installed\n")
	})

	t.Run("non-interactive retrieval times out without output", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-hang")
		started := time.Now()

		got := runCLI(t, binary, environment, "get", "op://vault/private-item/field")
		elapsed := time.Since(started)

		assertControlledGetFailure(t, got, "Error: 1Password request timed out\n")
		if elapsed < 4*time.Second || elapsed > 8*time.Second {
			t.Errorf("expected a five second deadline, elapsed %s", elapsed)
		}
	})

	t.Run("interactive retrieval is cancellable without output", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-hang")
		started := time.Now()

		got := runCLIWithTerminalArgs(t, binary, environment, "", true, "get", "op://vault/private-item/field")

		assertControlledGetFailure(t, got, "Error: 1Password request interrupted\n")
		if elapsed := time.Since(started); elapsed > 4*time.Second {
			t.Errorf("interactive cancellation took %s", elapsed)
		}
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
printf '%%s|%%s|%%s|%%s\n' "$*" "$OP_ACCOUNT" "$OP_SESSION_work" "$NO_COLOR" >> %q
case "$1:$FAKE_OP_MODE" in
  whoami:get-auth-required)
    echo 'account@example.com'
    echo 'You are not currently signed in. arbitrary subprocess diagnostic' >&2
    exit 1
    ;;
  whoami:get-*)
    exit 0
    ;;
  read:get-exact)
    printf 'opaque value\nwith trailing newline\n'
    exit 0
    ;;
  read:get-empty)
    exit 0
    ;;
  read:get-binary)
    printf '\377\000A\n'
    exit 0
    ;;
  read:get-limit)
    /bin/dd if=/dev/zero bs=1048576 count=16 2>/dev/null
    exit 0
    ;;
  read:get-oversized)
    /bin/dd if=/dev/zero bs=1048576 count=16 2>/dev/null
    printf x
    exit 0
    ;;
  read:get-partial-failure)
    printf 'partial Secret Value'
    echo 'arbitrary subprocess diagnostic' >&2
    exit 23
    ;;
  read:get-auth-read-stdout)
    echo 'You are not currently signed in. arbitrary subprocess diagnostic'
    exit 1
    ;;
  read:get-invalid)
    echo 'invalid secret reference: arbitrary subprocess diagnostic' >&2
    exit 1
    ;;
  read:get-invalid-stdout)
    echo 'invalid secret reference: arbitrary subprocess diagnostic'
    exit 1
    ;;
  read:get-not-found)
    echo 'item not found: arbitrary subprocess diagnostic' >&2
    exit 1
    ;;
  read:get-unknown)
    printf 'partial Secret Value'
    echo 'arbitrary subprocess diagnostic' >&2
    exit 23
    ;;
  read:get-hang)
    while :; do :; done
    ;;
  whoami:ready)
    echo 'account@example.com'
    echo 'raw diagnostic' >&2
    exit 0
    ;;
  whoami:required)
    echo 'account@example.com'
    echo 'You are not currently signed in. raw diagnostic' >&2
    exit 1
    ;;
  whoami:required-stdout)
    echo 'You are not currently signed in. account@example.com'
    echo 'raw diagnostic' >&2
    exit 1
    ;;
  whoami:interactive)
    IFS= read -r answer
    test "$answer" = approved
    ;;
  whoami:error)
    echo 'account@example.com'
    echo 'raw diagnostic' >&2
    exit 7
    ;;
  whoami:hang)
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

	return runCLIWithTerminalArgs(t, binary, environment, input, cancel, "status")
}

func runCLIWithTerminalArgs(t *testing.T, binary string, environment testEnvironment, input string, cancel bool, args ...string) result {
	t.Helper()

	terminal, childTerminal, err := pty.Open()
	if err != nil {
		t.Fatalf("open terminal: %v", err)
	}
	defer func() { _ = terminal.Close() }()
	defer func() { _ = childTerminal.Close() }()

	command := exec.Command(binary, args...)
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

func assertSecretResult(t *testing.T, got result, want []byte) {
	t.Helper()

	if !bytes.Equal([]byte(got.stdout), want) {
		t.Errorf("Secret Value bytes differ (want length %d, got length %d)", len(want), len(got.stdout))
	}
	if got.stderr != "" {
		t.Errorf("unexpected stderr while retrieving Secret Value (length %d)", len(got.stderr))
	}
	if got.err != nil {
		t.Errorf("expected successful Secret Value retrieval: %v", got.err)
	}
}

func assertControlledGetFailure(t *testing.T, got result, wantStderr string) {
	t.Helper()

	if got.stdout != "" {
		t.Errorf("failed retrieval emitted stdout (length %d)", len(got.stdout))
	}
	if got.stderr != wantStderr {
		t.Errorf("controlled stderr mismatch (want length %d, got length %d)", len(wantStderr), len(got.stderr))
	}
	if got.err == nil {
		t.Error("expected nonzero exit status")
	}
}

func assertNotInvoked(t *testing.T, environment testEnvironment) {
	t.Helper()

	if _, err := os.Stat(filepath.Join(environment.fakeBin, "op-invoked")); !os.IsNotExist(err) {
		t.Errorf("fake op was invoked: %v", err)
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
