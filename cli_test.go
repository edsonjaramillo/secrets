package main_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
  cache       Manage Cache Entries
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

func TestGetCache(t *testing.T) {
	binary := buildCLI(t, "")

	t.Run("a miss retains a schema-versioned Cache Entry with protected files", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-binary")
		reference := "op://vault/item/field"
		before := time.Now().UTC().Add(-time.Second)

		got := runCLIWithUmask(t, binary, environment, "get", reference)

		assertSecretResult(t, got, []byte{0xff, 0x00, 'A', '\n'})
		root := cacheRoot(environment)
		identifier := referenceIdentifier(reference)
		metadata := readCacheMetadata(t, root)
		if metadata.Version != 1 || len(metadata.Entries) != 1 {
			t.Fatalf("unexpected metadata header or entry count: %+v", metadata)
		}
		entry := metadata.Entries[0]
		if entry.Reference != reference || entry.Identifier != identifier {
			t.Errorf("metadata did not preserve exact identity: %+v", entry)
		}
		cachedAt, err := time.Parse(time.RFC3339, entry.CachedAt)
		if err != nil || cachedAt.Before(before) || cachedAt.After(time.Now().UTC().Add(time.Second)) || cachedAt.Location() != time.UTC {
			t.Errorf("invalid successful UTC cache timestamp %q", entry.CachedAt)
		}
		value, err := os.ReadFile(filepath.Join(root, "values", identifier))
		if err != nil {
			t.Fatalf("read retained Secret Value: %v", err)
		}
		if !bytes.Equal(value, []byte{0xff, 0x00, 'A', '\n'}) {
			t.Error("retained Secret Value bytes differ")
		}
		metadataBytes, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata bytes: %v", err)
		}
		if bytes.Contains(metadataBytes, value) {
			t.Error("Secret Value entered metadata")
		}
		assertMode(t, root, 0o700)
		assertMode(t, filepath.Join(root, "values"), 0o700)
		assertMode(t, filepath.Join(root, "metadata.json"), 0o600)
		assertMode(t, filepath.Join(root, "cache.lock"), 0o600)
		assertMode(t, filepath.Join(root, "values", identifier), 0o600)
		assertNoTemporaryFiles(t, root)
		assertNoTemporaryFiles(t, filepath.Join(root, "values"))
	})

	t.Run("a hit emits exact bytes without invoking op or changing metadata", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		reference := "op://vault/item/field"
		first := runCLI(t, binary, environment, "get", reference)
		assertSecretResult(t, first, []byte("opaque value\nwith trailing newline\n"))
		root := cacheRoot(environment)
		before, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read initial metadata: %v", err)
		}
		if err := os.Remove(filepath.Join(environment.fakeBin, "op")); err != nil {
			t.Fatalf("remove fake op: %v", err)
		}
		if err := os.Remove(filepath.Join(environment.fakeBin, "op-invoked")); err != nil {
			t.Fatalf("remove invocation marker: %v", err)
		}

		second := runCLI(t, binary, environment, "get", reference)

		assertSecretResult(t, second, []byte("opaque value\nwith trailing newline\n"))
		after, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata after hit: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Error("cache hit changed the cache timestamp")
		}
		assertNotInvoked(t, environment)
	})

	t.Run("textually different references retain different Cache Entries", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		references := []string{"op://vault/item/field", "op://vault/item/field?attribute=value"}
		for _, reference := range references {
			assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		}

		metadata := readCacheMetadata(t, cacheRoot(environment))
		if len(metadata.Entries) != 2 || metadata.Entries[0].Identifier == metadata.Entries[1].Identifier {
			t.Errorf("different exact references did not create distinct entries: %+v", metadata.Entries)
		}
		for _, reference := range references {
			if _, err := os.Stat(filepath.Join(cacheRoot(environment), "values", referenceIdentifier(reference))); err != nil {
				t.Errorf("missing value for distinct reference: %v", err)
			}
		}
	})

	t.Run("concurrent misses retain both Cache Entries", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact-slow")
		references := []string{"op://vault/first/field", "op://vault/second/field"}
		start := make(chan struct{})
		results := make(chan result, len(references))
		for _, reference := range references {
			go func() {
				<-start
				results <- runCommand(exec.Command(binary, "get", reference), environment)
			}()
		}
		close(start)
		for range references {
			assertSecretResult(t, <-results, []byte("opaque value\nwith trailing newline\n"))
		}

		metadata := readCacheMetadata(t, cacheRoot(environment))
		if len(metadata.Entries) != len(references) {
			t.Fatalf("concurrent misses retained %d entries, want %d", len(metadata.Entries), len(references))
		}
		for _, reference := range references {
			if _, err := os.Stat(filepath.Join(cacheRoot(environment), "values", referenceIdentifier(reference))); err != nil {
				t.Errorf("missing concurrent value: %v", err)
			}
		}
	})

	t.Run("a targeted hit rejects unsafe state without exposing cache data", func(t *testing.T) {
		tests := map[string]func(*testing.T, string, string){
			"unsafe root permissions": func(t *testing.T, root, _ string) {
				if err := os.Chmod(root, 0o755); err != nil {
					t.Fatalf("make cache root unsafe: %v", err)
				}
			},
			"unsafe values directory permissions": func(t *testing.T, root, _ string) {
				if err := os.Chmod(filepath.Join(root, "values"), 0o755); err != nil {
					t.Fatalf("make values directory unsafe: %v", err)
				}
			},
			"unsafe metadata permissions": func(t *testing.T, root, _ string) {
				if err := os.Chmod(filepath.Join(root, "metadata.json"), 0o644); err != nil {
					t.Fatalf("make metadata unsafe: %v", err)
				}
			},
			"unsafe requested value permissions": func(t *testing.T, root, identifier string) {
				if err := os.Chmod(filepath.Join(root, "values", identifier), 0o644); err != nil {
					t.Fatalf("make value unsafe: %v", err)
				}
			},
			"lock has wrong type": func(t *testing.T, root, _ string) {
				lockPath := filepath.Join(root, "cache.lock")
				if err := os.Remove(lockPath); err != nil {
					t.Fatalf("remove lock: %v", err)
				}
				if err := os.Mkdir(lockPath, 0o700); err != nil {
					t.Fatalf("replace lock with directory: %v", err)
				}
			},
			"foreign requested value ownership": func(t *testing.T, root, identifier string) {
				if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
					t.Skip("ownership guarantees are supported on macOS and Linux")
				}
				if os.Geteuid() != 0 {
					t.Skip("changing file ownership requires root")
				}
				if err := os.Chown(filepath.Join(root, "values", identifier), 1, -1); err != nil {
					t.Fatalf("change value owner: %v", err)
				}
			},
			"symlinked values directory": func(t *testing.T, root, _ string) {
				valuesPath := filepath.Join(root, "values")
				outside := filepath.Join(t.TempDir(), "values")
				if err := os.Rename(valuesPath, outside); err != nil {
					t.Fatalf("move values directory: %v", err)
				}
				if err := os.Symlink(outside, valuesPath); err != nil {
					t.Fatalf("symlink values directory: %v", err)
				}
			},
			"symlinked requested value": func(t *testing.T, root, identifier string) {
				valuePath := filepath.Join(root, "values", identifier)
				content, err := os.ReadFile(valuePath)
				if err != nil {
					t.Fatalf("read value before replacing it: %v", err)
				}
				outside := filepath.Join(t.TempDir(), "value")
				if err := os.WriteFile(outside, content, 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Remove(valuePath); err != nil {
					t.Fatalf("remove value: %v", err)
				}
				if err := os.Symlink(outside, valuePath); err != nil {
					t.Fatalf("symlink value: %v", err)
				}
			},
			"unknown metadata schema": func(t *testing.T, root, _ string) {
				metadata := readCacheMetadata(t, root)
				metadata.Version = 2
				writeCacheMetadata(t, root, metadata)
			},
			"hash mismatch": func(t *testing.T, root, _ string) {
				metadata := readCacheMetadata(t, root)
				metadata.Entries[0].Identifier = strings.Repeat("0", 64)
				writeCacheMetadata(t, root, metadata)
			},
		}
		for name, corrupt := range tests {
			t.Run(name, func(t *testing.T) {
				environment := isolatedEnvironment(t)
				environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
				reference := "op://vault/private-item/field"
				assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
				resetInvocation(t, environment)
				corrupt(t, cacheRoot(environment), referenceIdentifier(reference))

				got := runCLI(t, binary, environment, "get", reference)

				assertControlledGetFailure(t, got, "Error: cache state is invalid; inspect and remove the cache directory manually\n")
				if strings.Contains(got.stdout, "opaque value") || strings.Contains(got.stderr, reference) {
					t.Error("cache corruption failure exposed cache data")
				}
				assertNotInvoked(t, environment)
			})
		}
	})

	t.Run("an oversized targeted value fails with remediation guidance", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		reference := "op://vault/private-item/field"
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		valuePath := filepath.Join(cacheRoot(environment), "values", referenceIdentifier(reference))
		if err := os.Truncate(valuePath, 16*1024*1024+1); err != nil {
			t.Fatalf("make cached value oversized: %v", err)
		}
		resetInvocation(t, environment)

		got := runCLI(t, binary, environment, "get", reference)

		assertControlledGetFailure(t, got, "Error: cache state is invalid; inspect and remove the cache directory manually\n")
		assertNotInvoked(t, environment)
	})

	t.Run("a targeted hit ignores an unrelated missing value", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		target := "op://vault/item/field"
		unrelated := "op://vault/other/field"
		assertSecretResult(t, runCLI(t, binary, environment, "get", target), []byte("opaque value\nwith trailing newline\n"))
		assertSecretResult(t, runCLI(t, binary, environment, "get", unrelated), []byte("opaque value\nwith trailing newline\n"))
		if err := os.Remove(filepath.Join(cacheRoot(environment), "values", referenceIdentifier(unrelated))); err != nil {
			t.Fatalf("remove unrelated value: %v", err)
		}
		resetInvocation(t, environment)

		got := runCLI(t, binary, environment, "get", target)

		assertSecretResult(t, got, []byte("opaque value\nwith trailing newline\n"))
		assertNotInvoked(t, environment)
	})

	t.Run("a miss validates complete state before contacting op", func(t *testing.T) {
		tests := map[string]func(*testing.T, string, string){
			"malformed metadata": func(t *testing.T, root, _ string) {
				if err := os.WriteFile(filepath.Join(root, "metadata.json"), []byte("not json"), 0o600); err != nil {
					t.Fatalf("write malformed metadata: %v", err)
				}
			},
			"duplicate metadata key": func(t *testing.T, root, _ string) {
				content := []byte(`{"version":2,"version":1,"entries":[]}`)
				if err := os.WriteFile(filepath.Join(root, "metadata.json"), content, 0o600); err != nil {
					t.Fatalf("write duplicate metadata key: %v", err)
				}
			},
			"missing indexed value": func(t *testing.T, root, identifier string) {
				if err := os.Remove(filepath.Join(root, "values", identifier)); err != nil {
					t.Fatalf("remove indexed value: %v", err)
				}
			},
			"orphan value": func(t *testing.T, root, _ string) {
				if err := os.WriteFile(filepath.Join(root, "values", strings.Repeat("f", 64)), []byte("orphan"), 0o600); err != nil {
					t.Fatalf("write orphan value: %v", err)
				}
			},
			"unexpected root file": func(t *testing.T, root, _ string) {
				if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("unexpected"), 0o600); err != nil {
					t.Fatalf("write unexpected file: %v", err)
				}
			},
		}
		for name, corrupt := range tests {
			t.Run(name, func(t *testing.T) {
				environment := isolatedEnvironment(t)
				environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
				reference := "op://vault/item/field"
				assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
				resetInvocation(t, environment)
				corrupt(t, cacheRoot(environment), referenceIdentifier(reference))

				got := runCLI(t, binary, environment, "get", "op://vault/new/field")

				assertControlledGetFailure(t, got, "Error: cache state is invalid; inspect and remove the cache directory manually\n")
				assertNotInvoked(t, environment)
			})
		}
	})
}

type cacheMetadata struct {
	Version int `json:"version"`
	Entries []struct {
		Reference  string `json:"reference"`
		Identifier string `json:"identifier"`
		CachedAt   string `json:"cached_at"`
	} `json:"entries"`
}

func readCacheMetadata(t *testing.T, root string) cacheMetadata {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, "metadata.json"))
	if err != nil {
		t.Fatalf("read cache metadata: %v", err)
	}
	var metadata cacheMetadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		t.Fatalf("parse cache metadata: %v", err)
	}
	return metadata
}

func writeCacheMetadata(t *testing.T, root string, metadata cacheMetadata) {
	t.Helper()
	content, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal cache metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata.json"), append(content, '\n'), 0o600); err != nil {
		t.Fatalf("write cache metadata: %v", err)
	}
}

func resetInvocation(t *testing.T, environment testEnvironment) {
	t.Helper()
	if err := os.Remove(filepath.Join(environment.fakeBin, "op-invoked")); err != nil {
		t.Fatalf("remove invocation marker: %v", err)
	}
}

func cacheRoot(environment testEnvironment) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(environment.home, "Library", "Caches", "secrets")
	}
	return filepath.Join(environment.cache, "secrets")
}

func referenceIdentifier(reference string) string {
	digest := sha256.Sum256([]byte(reference))
	return hex.EncodeToString(digest[:])
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("mode for %s: want %04o, got %04o", path, want, got)
	}
}

func assertNoTemporaryFiles(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".temporary-") {
			t.Errorf("atomic write left temporary file %s", entry.Name())
		}
	}
}

func TestCacheList(t *testing.T) {
	binary := buildCLI(t, "")

	t.Run("accepts no positional arguments and documents human-readable output", func(t *testing.T) {
		environment := isolatedEnvironment(t)

		got := runCLI(t, binary, environment, "cache", "list", "unexpected")
		if got.err == nil || got.stdout != "" || !strings.HasPrefix(got.stderr, "Error: ") {
			t.Error("positional argument was not a concise usage failure")
		}
		assertDirectoryEmpty(t, environment.cache)

		help := runCLI(t, binary, environment, "cache", "list", "--help")
		if help.err != nil || help.stderr != "" || !strings.Contains(help.stdout, "human-readable") {
			t.Errorf("list help does not document human-readable output: %+v", help)
		}
	})

	t.Run("absent and empty caches produce no output without creating state", func(t *testing.T) {
		environment := isolatedEnvironment(t)

		assertResult(t, runCLI(t, binary, environment, "cache", "list"), "", "", false)
		assertDirectoryEmpty(t, environment.cache)

		createEmptyCache(t, environment)
		assertResult(t, runCLI(t, binary, environment, "cache", "list"), "", "", false)
	})

	t.Run("sorts complete state and re-reads it on each invocation", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		laterReference := "op://vault/zeta/field"
		earlierReference := "op://vault/alpha/field"
		assertSecretResult(t, runCLI(t, binary, environment, "get", laterReference), []byte("opaque value\nwith trailing newline\n"))

		first := runCLI(t, binary, environment, "cache", "list")
		if first.err != nil || first.stderr != "" || !strings.HasSuffix(first.stdout, "\t"+laterReference+"\n") {
			t.Errorf("unexpected initial listing: %+v", first)
		}

		assertSecretResult(t, runCLI(t, binary, environment, "get", earlierReference), []byte("opaque value\nwith trailing newline\n"))
		metadata := readCacheMetadata(t, cacheRoot(environment))
		metadata.Entries[0].CachedAt = "2024-01-02T03:04:05Z"
		metadata.Entries[1].CachedAt = "2025-06-07T08:09:10Z"
		metadata.Entries[0], metadata.Entries[1] = metadata.Entries[1], metadata.Entries[0]
		writeCacheMetadata(t, cacheRoot(environment), metadata)

		got := runCLI(t, binary, environment, "cache", "list")
		want := "2024-01-02T03:04:05Z\t" + earlierReference + "\n" +
			"2025-06-07T08:09:10Z\t" + laterReference + "\n"
		assertResult(t, got, want, "", false)
		if strings.Contains(got.stdout+got.stderr, "opaque value") {
			t.Error("listing exposed a Secret Value")
		}
	})

	for name, corrupt := range map[string]func(*testing.T, testEnvironment, string){
		"missing value": func(t *testing.T, environment testEnvironment, reference string) {
			if err := os.Remove(filepath.Join(cacheRoot(environment), "values", referenceIdentifier(reference))); err != nil {
				t.Fatalf("remove value: %v", err)
			}
		},
		"oversized value": func(t *testing.T, environment testEnvironment, reference string) {
			if err := os.Truncate(filepath.Join(cacheRoot(environment), "values", referenceIdentifier(reference)), 16*1024*1024+1); err != nil {
				t.Fatalf("enlarge value: %v", err)
			}
		},
		"invalid reference": func(t *testing.T, environment testEnvironment, reference string) {
			root := cacheRoot(environment)
			metadata := readCacheMetadata(t, root)
			invalidReference := "not-a-reference"
			for index := range metadata.Entries {
				if metadata.Entries[index].Reference == reference {
					oldIdentifier := metadata.Entries[index].Identifier
					metadata.Entries[index].Reference = invalidReference
					metadata.Entries[index].Identifier = referenceIdentifier(invalidReference)
					if err := os.Rename(filepath.Join(root, "values", oldIdentifier), filepath.Join(root, "values", metadata.Entries[index].Identifier)); err != nil {
						t.Fatalf("rename value for invalid reference: %v", err)
					}
				}
			}
			writeCacheMetadata(t, root, metadata)
		},
	} {
		t.Run("validates all state before emitting for "+name, func(t *testing.T) {
			environment := isolatedEnvironment(t)
			environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
			privateReference := "op://vault/private/field"
			for _, reference := range []string{"op://vault/first/field", privateReference} {
				assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
			}
			corrupt(t, environment, privateReference)

			got := runCLI(t, binary, environment, "cache", "list")
			assertResult(t, got, "", "Error: cache state is invalid; inspect and remove the cache directory manually\n", true)
			if strings.Contains(got.stdout+got.stderr, "opaque value") {
				t.Error("corruption diagnostic exposed a Secret Value")
			}
		})
	}
}

func TestCacheClear(t *testing.T) {
	binary := buildCLI(t, "")

	t.Run("requires exactly one Secret Reference or --all before touching state", func(t *testing.T) {
		for _, args := range [][]string{
			{"cache", "clear"},
			{"cache", "clear", "--all", "op://vault/item/field"},
			{"cache", "clear", "op://vault/item/field", "--all"},
			{"cache", "clear", "op://vault/one/field", "op://vault/two/field"},
			{"cache", "clear", "not-a-reference"},
		} {
			environment := isolatedEnvironment(t)
			got := runCLI(t, binary, environment, args...)
			if got.err == nil || got.stdout != "" || !strings.HasPrefix(got.stderr, "Error: ") {
				t.Errorf("arguments %v were not a concise failure: %+v", args, got)
			}
			assertDirectoryEmpty(t, environment.cache)
			assertNotInvoked(t, environment)
		}
	})

	t.Run("help describes logical removal without secure-erasure claims", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		got := runCLI(t, binary, environment, "cache", "clear", "--help")

		if got.err != nil || got.stderr != "" {
			t.Fatalf("clear help failed: %+v", got)
		}
		for _, phrase := range []string{"logical", "secure", "storage media", "snapshots", "backups"} {
			if !strings.Contains(strings.ToLower(got.stdout), phrase) {
				t.Errorf("clear help does not contain %q: %q", phrase, got.stdout)
			}
		}
	})

	t.Run("unknown individual entries fail without mutation", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		reference := "op://vault/item/field"
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		root := cacheRoot(environment)
		beforeMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata before unknown clear: %v", err)
		}

		got := runCLI(t, binary, environment, "cache", "clear", "op://vault/missing/field")

		assertResult(t, got, "", "Error: cache entry not found\n", true)
		afterMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata after unknown clear: %v", err)
		}
		if !bytes.Equal(beforeMetadata, afterMetadata) {
			t.Error("unknown clear changed metadata")
		}
		if _, err := os.Stat(filepath.Join(root, "values", referenceIdentifier(reference))); err != nil {
			t.Fatalf("unknown clear removed known value: %v", err)
		}
	})

	t.Run("single clear removes the Cache Entry and forces the next get to miss", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		reference := "op://vault/item/field"
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		root := cacheRoot(environment)

		got := runCLI(t, binary, environment, "cache", "clear", reference)

		assertResult(t, got, "", "", false)
		metadata := readCacheMetadata(t, root)
		if len(metadata.Entries) != 0 {
			t.Fatalf("clear retained metadata entries: %+v", metadata.Entries)
		}
		if _, err := os.Stat(filepath.Join(root, "values", referenceIdentifier(reference))); !os.IsNotExist(err) {
			t.Errorf("clear retained value: %v", err)
		}
		resetInvocation(t, environment)
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		if _, err := os.Stat(filepath.Join(environment.fakeBin, "op-invoked")); err != nil {
			t.Fatalf("next get did not invoke op after clear: %v", err)
		}
	})

	t.Run("clear --all removes every Cache Entry silently", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		references := []string{"op://vault/first/field", "op://vault/second/field"}
		for _, reference := range references {
			assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		}

		got := runCLI(t, binary, environment, "cache", "clear", "--all")

		assertResult(t, got, "", "", false)
		metadata := readCacheMetadata(t, cacheRoot(environment))
		if len(metadata.Entries) != 0 {
			t.Fatalf("clear --all retained metadata entries: %+v", metadata.Entries)
		}
		entries, err := os.ReadDir(filepath.Join(cacheRoot(environment), "values"))
		if err != nil {
			t.Fatalf("read values after clear --all: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("clear --all retained value files: %v", entries)
		}
	})

	t.Run("absent and empty clear --all commands succeed without creating state", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		assertResult(t, runCLI(t, binary, environment, "cache", "clear", "--all"), "", "", false)
		assertDirectoryEmpty(t, environment.cache)

		createEmptyCache(t, environment)
		before, err := os.ReadFile(filepath.Join(cacheRoot(environment), "metadata.json"))
		if err != nil {
			t.Fatalf("read empty metadata before clear --all: %v", err)
		}
		assertResult(t, runCLI(t, binary, environment, "cache", "clear", "--all"), "", "", false)
		after, err := os.ReadFile(filepath.Join(cacheRoot(environment), "metadata.json"))
		if err != nil {
			t.Fatalf("read empty metadata after clear --all: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Error("empty clear --all changed metadata")
		}
	})

	t.Run("clear --all validates complete state before removing anything", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		environment.variables = append(environment.variables, "FAKE_OP_MODE=get-exact")
		references := []string{"op://vault/first/field", "op://vault/second/field"}
		for _, reference := range references {
			assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		}
		root := cacheRoot(environment)
		metadataBefore, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata before corruption: %v", err)
		}
		valuePath := filepath.Join(root, "values", referenceIdentifier(references[1]))
		if err := os.Remove(valuePath); err != nil {
			t.Fatalf("remove value for corruption: %v", err)
		}
		firstValuePath := filepath.Join(root, "values", referenceIdentifier(references[0]))
		valueBefore, err := os.ReadFile(firstValuePath)
		if err != nil {
			t.Fatalf("read unaffected value before clear: %v", err)
		}

		got := runCLI(t, binary, environment, "cache", "clear", "--all")

		assertResult(t, got, "", "Error: cache state is invalid; inspect and remove the cache directory manually\n", true)
		metadataAfter, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata after rejected clear: %v", err)
		}
		if !bytes.Equal(metadataBefore, metadataAfter) {
			t.Error("corrupt clear --all changed metadata")
		}
		valueAfter, err := os.ReadFile(firstValuePath)
		if err != nil {
			t.Fatalf("read unaffected value after rejected clear: %v", err)
		}
		if !bytes.Equal(valueBefore, valueAfter) {
			t.Error("corrupt clear --all changed an unaffected value")
		}
	})
}

func TestCacheRevalidate(t *testing.T) {
	binary := buildCLI(t, "")
	reference := "op://vault/item/field"

	t.Run("requires exactly one valid Secret Reference before touching state", func(t *testing.T) {
		for _, args := range [][]string{
			{"cache", "revalidate"},
			{"cache", "revalidate", "op://vault/one/field", "op://vault/two/field"},
			{"cache", "revalidate", "not-a-reference"},
			{"cache", "revalidate", "--all"},
		} {
			environment := isolatedEnvironment(t)
			got := runCLI(t, binary, environment, args...)
			if got.err == nil || got.stdout != "" || !strings.HasPrefix(got.stderr, "Error: ") {
				t.Errorf("arguments %v were not a concise failure: %+v", args, got)
			}
			assertDirectoryEmpty(t, environment.cache)
			assertNotInvoked(t, environment)
		}
	})

	t.Run("missing Cache Entry fails without contacting op or creating state", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		setEnvironmentVariable(&environment, "FAKE_OP_MODE", "revalidate-exact")

		got := runCLI(t, binary, environment, "cache", "revalidate", reference)

		assertResult(t, got, "", "Error: cache entry not found\n", true)
		assertDirectoryEmpty(t, environment.cache)
		assertNotInvoked(t, environment)
	})

	t.Run("unknown Cache Entry fails without mutation or contacting op", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		setEnvironmentVariable(&environment, "FAKE_OP_MODE", "get-exact")
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		root := cacheRoot(environment)
		beforeMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata before unknown Revalidation: %v", err)
		}
		resetInvocation(t, environment)

		got := runCLI(t, binary, environment, "cache", "revalidate", "op://vault/missing/field")

		assertResult(t, got, "", "Error: cache entry not found\n", true)
		assertNotInvoked(t, environment)
		afterMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata after unknown Revalidation: %v", err)
		}
		if !bytes.Equal(beforeMetadata, afterMetadata) {
			t.Error("unknown Revalidation changed metadata")
		}
	})

	t.Run("successful Revalidation replaces unchanged and changed Secret Values and timestamp", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			mode  string
			value []byte
		}{
			{name: "changed value", mode: "revalidate-exact", value: []byte("revalidated value\nwith trailing newline\n")},
			{name: "unchanged value", mode: "revalidate-same", value: []byte("opaque value\nwith trailing newline\n")},
		} {
			t.Run(test.name, func(t *testing.T) {
				environment := isolatedEnvironment(t)
				setEnvironmentVariable(&environment, "FAKE_OP_MODE", "get-exact")
				assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))

				root := cacheRoot(environment)
				metadata := readCacheMetadata(t, root)
				metadata.Entries[0].CachedAt = "2020-01-02T03:04:05Z"
				writeCacheMetadata(t, root, metadata)
				beforeMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
				if err != nil {
					t.Fatalf("read metadata before Revalidation: %v", err)
				}

				setEnvironmentVariable(&environment, "FAKE_OP_MODE", test.mode)
				got := runCLI(t, binary, environment, "cache", "revalidate", reference)

				assertResult(t, got, "", "", false)
				afterMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
				if err != nil {
					t.Fatalf("read metadata after Revalidation: %v", err)
				}
				if bytes.Equal(beforeMetadata, afterMetadata) {
					t.Error("successful Revalidation did not update the cache timestamp")
				}
				updated := readCacheMetadata(t, root)
				cachedAt, err := time.Parse(time.RFC3339, updated.Entries[0].CachedAt)
				if err != nil || cachedAt.Equal(time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)) || cachedAt.Location() != time.UTC {
					t.Errorf("successful Revalidation wrote an invalid replacement timestamp: %q", updated.Entries[0].CachedAt)
				}
				value, err := os.ReadFile(filepath.Join(root, "values", referenceIdentifier(reference)))
				if err != nil {
					t.Fatalf("read replaced Secret Value: %v", err)
				}
				if !bytes.Equal(value, test.value) {
					t.Errorf("revalidated Secret Value = %q, want %q", value, test.value)
				}
				if got.stdout != "" || got.stderr != "" {
					t.Error("successful Revalidation was not silent")
				}
			})
		}
	})

	for _, test := range []struct {
		name string
		mode string
		want string
	}{
		{name: "authentication failure", mode: "get-auth-required", want: "Error: authentication required; run `op signin` or enable 1Password desktop-app CLI integration\n"},
		{name: "retrieval failure", mode: "get-unknown", want: "Error: 1Password command failed with exit code 23\n"},
		{name: "oversized output", mode: "get-oversized", want: "Error: secret value exceeds the 16 MiB limit\n"},
	} {
		t.Run(test.name+" preserves the previous Cache Entry", func(t *testing.T) {
			environment := isolatedEnvironment(t)
			setEnvironmentVariable(&environment, "FAKE_OP_MODE", "get-exact")
			assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
			root := cacheRoot(environment)
			beforeMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
			if err != nil {
				t.Fatalf("read metadata before failed Revalidation: %v", err)
			}
			beforeValue, err := os.ReadFile(filepath.Join(root, "values", referenceIdentifier(reference)))
			if err != nil {
				t.Fatalf("read value before failed Revalidation: %v", err)
			}

			setEnvironmentVariable(&environment, "FAKE_OP_MODE", test.mode)
			got := runCLI(t, binary, environment, "cache", "revalidate", reference)

			assertResult(t, got, "", test.want, true)
			afterMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
			if err != nil {
				t.Fatalf("read metadata after failed Revalidation: %v", err)
			}
			if !bytes.Equal(beforeMetadata, afterMetadata) {
				t.Error("failed Revalidation changed the cache timestamp")
			}
			afterValue, err := os.ReadFile(filepath.Join(root, "values", referenceIdentifier(reference)))
			if err != nil {
				t.Fatalf("read value after failed Revalidation: %v", err)
			}
			if !bytes.Equal(beforeValue, afterValue) {
				t.Error("failed Revalidation changed the previous Secret Value")
			}
			if strings.Contains(got.stdout+got.stderr, reference) || strings.Contains(got.stdout+got.stderr, "opaque value") {
				t.Error("failed Revalidation exposed private cache data")
			}
		})
	}

	t.Run("interruption preserves the previous Cache Entry", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		setEnvironmentVariable(&environment, "FAKE_OP_MODE", "get-exact")
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		root := cacheRoot(environment)
		beforeMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata before interrupted Revalidation: %v", err)
		}
		beforeValue, err := os.ReadFile(filepath.Join(root, "values", referenceIdentifier(reference)))
		if err != nil {
			t.Fatalf("read value before interrupted Revalidation: %v", err)
		}
		resetInvocation(t, environment)
		setEnvironmentVariable(&environment, "FAKE_OP_MODE", "get-hang")

		got := runCLIWithTerminalArgs(t, binary, environment, "", true, "cache", "revalidate", reference)

		assertResult(t, got, "", "Error: 1Password request interrupted\n", true)
		afterMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata after interrupted Revalidation: %v", err)
		}
		if !bytes.Equal(beforeMetadata, afterMetadata) {
			t.Error("interrupted Revalidation changed the cache timestamp")
		}
		afterValue, err := os.ReadFile(filepath.Join(root, "values", referenceIdentifier(reference)))
		if err != nil {
			t.Fatalf("read value after interrupted Revalidation: %v", err)
		}
		if !bytes.Equal(beforeValue, afterValue) {
			t.Error("interrupted Revalidation changed the previous Secret Value")
		}
	})

	t.Run("validates complete state before contacting op", func(t *testing.T) {
		environment := isolatedEnvironment(t)
		setEnvironmentVariable(&environment, "FAKE_OP_MODE", "get-exact")
		assertSecretResult(t, runCLI(t, binary, environment, "get", reference), []byte("opaque value\nwith trailing newline\n"))
		root := cacheRoot(environment)
		beforeMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata before corruption: %v", err)
		}
		if err := os.Remove(filepath.Join(root, "values", referenceIdentifier(reference))); err != nil {
			t.Fatalf("remove indexed value: %v", err)
		}
		resetInvocation(t, environment)
		setEnvironmentVariable(&environment, "FAKE_OP_MODE", "revalidate-exact")

		got := runCLI(t, binary, environment, "cache", "revalidate", reference)

		assertResult(t, got, "", "Error: cache state is invalid; inspect and remove the cache directory manually\n", true)
		assertNotInvoked(t, environment)
		afterMetadata, err := os.ReadFile(filepath.Join(root, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata after rejected Revalidation: %v", err)
		}
		if !bytes.Equal(beforeMetadata, afterMetadata) {
			t.Error("validation failure changed metadata")
		}
	})
}

func setEnvironmentVariable(environment *testEnvironment, name, value string) {
	prefix := name + "="
	for index, variable := range environment.variables {
		if strings.HasPrefix(variable, prefix) {
			environment.variables[index] = prefix + value
			return
		}
	}
	environment.variables = append(environment.variables, prefix+value)
}

func createEmptyCache(t *testing.T, environment testEnvironment) {
	t.Helper()
	root := cacheRoot(environment)
	if err := os.MkdirAll(filepath.Join(root, "values"), 0o700); err != nil {
		t.Fatalf("create empty cache directories: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cache.lock"), nil, 0o600); err != nil {
		t.Fatalf("create cache lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata.json"), []byte("{\"version\":1,\"entries\":[]}\n"), 0o600); err != nil {
		t.Fatalf("create empty cache metadata: %v", err)
	}
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
  whoami:revalidate-*)
    exit 0
    ;;
  read:get-exact)
    printf 'opaque value\nwith trailing newline\n'
    exit 0
    ;;
  read:revalidate-exact)
    printf 'revalidated value\nwith trailing newline\n'
    exit 0
    ;;
  read:revalidate-same)
    printf 'opaque value\nwith trailing newline\n'
    exit 0
    ;;
  read:get-exact-slow)
    sleep 0.1
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

	return runCommand(exec.Command(binary, args...), environment)
}

func runCLIWithUmask(t *testing.T, binary string, environment testEnvironment, args ...string) result {
	t.Helper()

	commandArgs := append([]string{"-c", `umask 0777; exec "$@"`, "sh", binary}, args...)
	return runCommand(exec.Command("/bin/sh", commandArgs...), environment)
}

func runCommand(command *exec.Cmd, environment testEnvironment) result {
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
