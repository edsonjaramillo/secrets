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

const (
	schemaVersion   = 1
	directoryMode   = 0o700
	regularFileMode = 0o600
)

var (
	// ErrInvalidState reports cache state that cannot be trusted.
	ErrInvalidState = errors.New("cache state is invalid")
	// ErrUnsupportedPlatform reports a platform where ownership cannot be verified.
	ErrUnsupportedPlatform = errors.New("cache security checks are unsupported on this platform")
)

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
	if !ownershipChecksSupported() {
		return Store{}, ErrUnsupportedPlatform
	}
	parent, err := os.UserCacheDir()
	if err != nil {
		return Store{}, err
	}
	return Store{root: filepath.Join(parent, "secrets")}, nil
}

// Lookup returns the exact bytes for reference when its Cache Entry exists.
func (store Store) Lookup(reference string) ([]byte, bool, error) {
	lock, exists, err := store.acquireLock(false)
	if err != nil || !exists {
		return nil, false, err
	}
	defer releaseLock(lock)

	state, exists, err := store.readMetadata()
	if err != nil || !exists {
		return nil, false, err
	}

	identifier := Identifier(reference)
	var matched *entry
	for index := range state.Entries {
		candidate := &state.Entries[index]
		if candidate.Reference == reference {
			if matched != nil || candidate.Identifier != identifier {
				return nil, false, ErrInvalidState
			}
			matched = candidate
		}
	}
	if matched == nil {
		return nil, false, nil
	}

	valuePath := filepath.Join(store.root, "values", matched.Identifier)
	if err := validateNode(valuePath, false); err != nil {
		return nil, false, ErrInvalidState
	}
	value, err := os.ReadFile(valuePath)
	if err != nil {
		return nil, false, ErrInvalidState
	}
	return value, true, nil
}

// Validate verifies complete existing state before cache state is mutated.
func (store Store) Validate() error {
	lock, exists, err := store.acquireLock(false)
	if err != nil || !exists {
		return err
	}
	defer releaseLock(lock)
	return store.validateUnlocked()
}

func (store Store) validateUnlocked() error {
	state, exists, err := store.readMetadata()
	if err != nil || !exists {
		return err
	}

	return store.validateValues(state)
}

func (store Store) validateValues(state metadata) error {
	expected := make(map[string]struct{}, len(state.Entries))
	for _, item := range state.Entries {
		expected[item.Identifier] = struct{}{}
		if err := validateNode(filepath.Join(store.root, "values", item.Identifier), false); err != nil {
			return ErrInvalidState
		}
	}

	files, err := os.ReadDir(filepath.Join(store.root, "values"))
	if err != nil || len(files) != len(expected) {
		return ErrInvalidState
	}
	for _, file := range files {
		if _, ok := expected[file.Name()]; !ok {
			return ErrInvalidState
		}
		if err := validateNode(filepath.Join(store.root, "values", file.Name()), false); err != nil {
			return ErrInvalidState
		}
	}
	return nil
}

// Put atomically replaces the individual value and metadata files for a successful retrieval.
func (store Store) Put(reference string, value []byte, cachedAt time.Time) error {
	if _, err := os.Lstat(store.root); errors.Is(err, os.ErrNotExist) {
		if err := store.ensureLayout(); err != nil {
			return err
		}
	} else if err != nil {
		return ErrInvalidState
	}

	lock, exists, err := store.acquireLock(true)
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidState
	}
	defer releaseLock(lock)

	state, err := store.stateForMutation()
	if err != nil {
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

func (store Store) stateForMutation() (metadata, error) {
	if _, err := os.Lstat(filepath.Join(store.root, "metadata.json")); errors.Is(err, os.ErrNotExist) {
		children, readErr := os.ReadDir(store.root)
		if readErr != nil || len(children) != 2 || validateNode(filepath.Join(store.root, "values"), true) != nil ||
			validateNode(filepath.Join(store.root, "cache.lock"), false) != nil {
			return metadata{}, ErrInvalidState
		}
		for _, child := range children {
			if child.Name() != "values" && child.Name() != "cache.lock" {
				return metadata{}, ErrInvalidState
			}
		}
		values, valuesErr := os.ReadDir(filepath.Join(store.root, "values"))
		if valuesErr != nil || len(values) != 0 {
			return metadata{}, ErrInvalidState
		}
		return metadata{Version: schemaVersion, Entries: []entry{}}, nil
	} else if err != nil {
		return metadata{}, ErrInvalidState
	}

	state, exists, err := store.readMetadata()
	if err != nil || !exists {
		return metadata{}, ErrInvalidState
	}
	if err := store.validateValues(state); err != nil {
		return metadata{}, err
	}
	return state, nil
}

func (store Store) acquireLock(exclusive bool) (*os.File, bool, error) {
	if _, err := os.Lstat(store.root); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil || validateNode(store.root, true) != nil {
		return nil, false, ErrInvalidState
	}

	lockPath := filepath.Join(store.root, "cache.lock")
	if err := validateNode(lockPath, false); err != nil {
		return nil, false, ErrInvalidState
	}
	lock, err := os.OpenFile(lockPath, os.O_RDWR, regularFileMode)
	if err != nil {
		return nil, false, ErrInvalidState
	}
	info, err := lock.Stat()
	if err != nil || validateInfo(info, false) != nil || lockFile(lock, exclusive) != nil {
		_ = lock.Close()
		return nil, false, ErrInvalidState
	}
	return lock, true, nil
}

func releaseLock(lock *os.File) {
	_ = unlockFile(lock)
	_ = lock.Close()
}

func (store Store) readMetadata() (metadata, bool, error) {
	rootInfo, err := os.Lstat(store.root)
	if errors.Is(err, os.ErrNotExist) {
		return metadata{}, false, nil
	}
	if err != nil || validateInfo(rootInfo, true) != nil {
		return metadata{}, false, ErrInvalidState
	}

	children, err := os.ReadDir(store.root)
	if err != nil || len(children) != 3 {
		return metadata{}, false, ErrInvalidState
	}
	expected := map[string]bool{"metadata.json": false, "values": true, "cache.lock": false}
	for _, child := range children {
		directory, ok := expected[child.Name()]
		if !ok || validateNode(filepath.Join(store.root, child.Name()), directory) != nil {
			return metadata{}, false, ErrInvalidState
		}
	}

	content, err := os.ReadFile(filepath.Join(store.root, "metadata.json"))
	if err != nil {
		return metadata{}, false, ErrInvalidState
	}

	if !hasUniqueJSONKeys(content) {
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
	if !validIndex(state) {
		return metadata{}, false, ErrInvalidState
	}
	return state, true, nil
}

func hasUniqueJSONKeys(content []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidState
			}
			if _, duplicate := keys[key]; duplicate {
				return ErrInvalidState
			}
			keys[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidState
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter]) {
		return ErrInvalidState
	}
	return nil
}

func validIndex(state metadata) bool {
	identifiers := make(map[string]struct{}, len(state.Entries))
	references := make(map[string]struct{}, len(state.Entries))
	for _, item := range state.Entries {
		if item.Reference == "" || item.Identifier != Identifier(item.Reference) || !validTimestamp(item.CachedAt) {
			return false
		}
		if _, duplicate := identifiers[item.Identifier]; duplicate {
			return false
		}
		if _, duplicate := references[item.Reference]; duplicate {
			return false
		}
		identifiers[item.Identifier] = struct{}{}
		references[item.Reference] = struct{}{}
	}
	return true
}

func validateNode(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ErrInvalidState
	}
	return validateInfo(info, directory)
}

func validateInfo(info os.FileInfo, directory bool) error {
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return ErrInvalidState
	}
	expectedMode := os.FileMode(regularFileMode)
	if directory {
		expectedMode = directoryMode
	}
	if info.Mode().Perm() != expectedMode || !ownedByCurrentUser(info) {
		return ErrInvalidState
	}
	return nil
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
	lockPath := filepath.Join(store.root, "cache.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, regularFileMode)
	if errors.Is(err, os.ErrExist) {
		return validateNode(lockPath, false)
	}
	if err != nil {
		return err
	}
	if err := lock.Chmod(regularFileMode); err != nil {
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
	err := os.Mkdir(path, directoryMode)
	if err == nil {
		return os.Chmod(path, directoryMode)
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

	if err := temporary.Chmod(regularFileMode); err != nil {
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
