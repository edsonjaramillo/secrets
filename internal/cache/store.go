package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const schemaVersion = 1

// ErrInvalidState reports cache state that cannot be trusted.
var ErrInvalidState = errors.New("cache state is invalid")

// Store persists Cache Entries below the operating system user cache directory.
type Store struct {
	root string
}

type metadata struct {
	Version int     `json:"version"`
	Entries []entry `json:"entries"`
}

type entry struct {
	Reference  string `json:"reference"`
	Identifier string `json:"identifier"`
	CachedAt   string `json:"cached_at"`
}

// NewStore selects the dedicated cache root.
func NewStore() (Store, error) {
	parent, err := os.UserCacheDir()
	if err != nil {
		return Store{}, err
	}
	return Store{root: filepath.Join(parent, "secrets")}, nil
}

// Lookup returns the exact bytes for reference when its Cache Entry exists.
func (store Store) Lookup(reference string) ([]byte, bool, error) {
	state, exists, err := store.readMetadata()
	if err != nil || !exists {
		return nil, false, err
	}

	identifier := Identifier(reference)
	var matched *entry
	for index := range state.Entries {
		candidate := &state.Entries[index]
		if candidate.Reference != reference {
			continue
		}
		if matched != nil || candidate.Identifier != identifier || !validTimestamp(candidate.CachedAt) {
			return nil, false, ErrInvalidState
		}
		matched = candidate
	}
	if matched == nil {
		return nil, false, nil
	}

	value, err := os.ReadFile(filepath.Join(store.root, "values", matched.Identifier))
	if err != nil {
		return nil, false, ErrInvalidState
	}
	return value, true, nil
}

// Validate verifies complete existing state before a new Cache Entry is added.
func (store Store) Validate() error {
	state, exists, err := store.readMetadata()
	if err != nil || !exists {
		return err
	}

	expected := make(map[string]struct{}, len(state.Entries))
	seenReferences := make(map[string]struct{}, len(state.Entries))
	for _, item := range state.Entries {
		if item.Reference == "" || item.Identifier != Identifier(item.Reference) || !validTimestamp(item.CachedAt) {
			return ErrInvalidState
		}
		if _, duplicate := expected[item.Identifier]; duplicate {
			return ErrInvalidState
		}
		if _, duplicate := seenReferences[item.Reference]; duplicate {
			return ErrInvalidState
		}
		expected[item.Identifier] = struct{}{}
		seenReferences[item.Reference] = struct{}{}
		info, statErr := os.Stat(filepath.Join(store.root, "values", item.Identifier))
		if statErr != nil || !info.Mode().IsRegular() {
			return ErrInvalidState
		}
	}

	files, err := os.ReadDir(filepath.Join(store.root, "values"))
	if err != nil {
		return ErrInvalidState
	}
	if len(files) != len(expected) {
		return ErrInvalidState
	}
	for _, file := range files {
		if _, ok := expected[file.Name()]; !ok || !file.Type().IsRegular() {
			return ErrInvalidState
		}
	}
	return nil
}

// Put atomically replaces the individual value and metadata files for a successful retrieval.
func (store Store) Put(reference string, value []byte, cachedAt time.Time) error {
	if err := store.Validate(); err != nil {
		return err
	}
	state, exists, err := store.readMetadata()
	if err != nil {
		return err
	}
	if !exists {
		state = metadata{Version: schemaVersion, Entries: []entry{}}
	}
	if err := store.ensureLayout(); err != nil {
		return err
	}

	identifier := Identifier(reference)
	if err := atomicWrite(filepath.Join(store.root, "values", identifier), value); err != nil {
		return err
	}

	newEntry := entry{
		Reference:  reference,
		Identifier: identifier,
		CachedAt:   cachedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	replaced := false
	for index := range state.Entries {
		if state.Entries[index].Reference == reference {
			state.Entries[index] = newEntry
			replaced = true
			break
		}
	}
	if !replaced {
		state.Entries = append(state.Entries, newEntry)
	}
	sort.Slice(state.Entries, func(left, right int) bool {
		return state.Entries[left].Reference < state.Entries[right].Reference
	})

	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	content = append(content, '\n')
	return atomicWrite(filepath.Join(store.root, "metadata.json"), content)
}

// Identifier hashes the exact, complete Secret Reference.
func Identifier(reference string) string {
	digest := sha256.Sum256([]byte(reference))
	return hex.EncodeToString(digest[:])
}

func (store Store) readMetadata() (metadata, bool, error) {
	content, err := os.ReadFile(filepath.Join(store.root, "metadata.json"))
	if errors.Is(err, os.ErrNotExist) {
		if _, rootErr := os.Stat(store.root); errors.Is(rootErr, os.ErrNotExist) {
			return metadata{}, false, nil
		}
		return metadata{}, false, ErrInvalidState
	}
	if err != nil {
		return metadata{}, false, ErrInvalidState
	}

	var state metadata
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.Version != schemaVersion || state.Entries == nil {
		return metadata{}, false, ErrInvalidState
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return metadata{}, false, ErrInvalidState
	}
	return state, true, nil
}

func (store Store) ensureLayout() error {
	if err := makePrivateParents(filepath.Dir(store.root)); err != nil {
		return err
	}
	if err := makePrivateDirectory(store.root); err != nil {
		return err
	}
	if err := makePrivateDirectory(filepath.Join(store.root, "values")); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(store.root, "cache.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := lock.Chmod(0o600); err != nil {
		_ = lock.Close()
		return err
	}
	return lock.Close()
}

func makePrivateParents(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if parent := filepath.Dir(path); parent != path {
		if err := makePrivateParents(parent); err != nil {
			return err
		}
	}
	return makePrivateDirectory(path)
}

func makePrivateDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err == nil {
		return os.Chmod(path, 0o700)
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func atomicWrite(path string, content []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".temporary-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339) == value
}
