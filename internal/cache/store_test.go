package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClearAllReconcilesMetadataAfterPartialRemoval(t *testing.T) {
	if !ownershipChecksSupported() {
		t.Skip("ownership checks are unsupported on this platform")
	}

	root := t.TempDir()
	if err := os.Chmod(root, directoryMode); err != nil {
		t.Fatalf("protect test root: %v", err)
	}
	valuesPath := filepath.Join(root, "values")
	if err := os.Mkdir(valuesPath, directoryMode); err != nil {
		t.Fatalf("create values directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cache.lock"), nil, regularFileMode); err != nil {
		t.Fatalf("create cache lock: %v", err)
	}
	store := Store{root: root}
	references := []string{"op://vault/zeta/field", "op://vault/alpha/field"}
	state := metadata{Version: schemaVersion}
	for _, reference := range references {
		identifier := Identifier(reference)
		state.Entries = append(state.Entries, entry{
			Reference:  reference,
			Identifier: identifier,
			CachedAt:   "2026-01-02T03:04:05Z",
		})
		if err := os.WriteFile(filepath.Join(valuesPath, identifier), []byte(reference), regularFileMode); err != nil {
			t.Fatalf("write value: %v", err)
		}
	}
	if err := store.writeMetadata(state); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	if state, exists, err := store.readMetadata(); err != nil || !exists {
		t.Fatalf("read metadata before clear: state=%+v exists=%t err=%v", state, exists, err)
	} else if err := store.validateValues(state); err != nil {
		t.Fatalf("validate values before clear: %v", err)
	}

	injected := errors.New("injected removal failure")
	failedPath := filepath.Join(valuesPath, Identifier(references[0]))
	err := store.clearAll(func(path string) error {
		if path == failedPath {
			return injected
		}
		return os.Remove(path)
	})
	if !errors.Is(err, injected) {
		t.Fatalf("clear all error = %v, want injected failure", err)
	}

	remaining, err := store.readValidatedMetadata()
	if err != nil {
		t.Fatalf("read reconciled metadata: %v", err)
	}
	if len(remaining.Entries) != 1 || remaining.Entries[0].Reference != references[0] {
		t.Fatalf("reconciled metadata = %+v, want only %q", remaining.Entries, references[0])
	}
	if _, err := os.Stat(filepath.Join(valuesPath, Identifier(references[1]))); !os.IsNotExist(err) {
		t.Errorf("successfully removed value remains: %v", err)
	}
	if _, err := os.Stat(failedPath); err != nil {
		t.Errorf("failed removal value is missing: %v", err)
	}
}
