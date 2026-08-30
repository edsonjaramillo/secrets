package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	schemaVersion   = 1
	directoryMode   = 0o700
	regularFileMode = 0o600

	lockPollInterval = 10 * time.Millisecond

	// MaximumSecretValueSize bounds values accepted from or retained in the cache.
	MaximumSecretValueSize = 16 * 1024 * 1024
)

var (
	// ErrInvalidState reports cache state that cannot be trusted.
	ErrInvalidState = errors.New("cache state is invalid")
	// ErrEntryNotFound reports a requested Cache Entry that does not exist.
	ErrEntryNotFound = errors.New("cache entry not found")
	// ErrUnsupportedPlatform reports a platform where ownership cannot be verified.
	ErrUnsupportedPlatform = errors.New("cache security checks are unsupported on this platform")
)

// Store persists Cache Entries below the operating system user cache directory.
type Store struct {
	root string
}

// ListingEntry contains the non-secret fields shown by cache administration commands.
type ListingEntry struct {
	Reference string
	CachedAt  string
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
	return store.LookupContext(context.Background(), reference)
}

// LookupContext is Lookup with a cancellation-aware lock acquisition.
func (store Store) LookupContext(ctx context.Context, reference string) ([]byte, bool, error) {
	lock, exists, err := store.acquireLock(ctx, false)
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
	if err := validateValueNode(valuePath); err != nil {
		return nil, false, ErrInvalidState
	}
	value, err := os.ReadFile(valuePath)
	if err != nil {
		return nil, false, ErrInvalidState
	}
	return value, true, nil
}

// List returns every Cache Entry after validating complete cache state.
func (store Store) List() ([]ListingEntry, error) {
	return store.ListContext(context.Background())
}

// ListContext is List with a cancellation-aware lock acquisition.
func (store Store) ListContext(ctx context.Context) ([]ListingEntry, error) {
	lock, exists, err := store.acquireLock(ctx, false)
	if err != nil || !exists {
		return nil, err
	}
	defer releaseLock(lock)

	state, err := store.readValidatedMetadata()
	if err != nil {
		return nil, err
	}

	entries := make([]ListingEntry, len(state.Entries))
	for index, item := range state.Entries {
		entries[index] = ListingEntry{Reference: item.Reference, CachedAt: item.CachedAt}
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Reference < entries[right].Reference
	})
	return entries, nil
}

// Clear removes one Cache Entry without producing output.
func (store Store) Clear(reference string) error {
	return store.ClearContext(context.Background(), reference)
}

// ClearContext is Clear with a cancellation-aware lock acquisition.
func (store Store) ClearContext(ctx context.Context, reference string) error {
	lock, exists, err := store.acquireLock(ctx, true)
	if err != nil {
		return err
	}
	if !exists {
		return ErrEntryNotFound
	}
	defer releaseLock(lock)

	state, err := store.readValidatedMetadata()
	if err != nil {
		return err
	}

	index := -1
	for current, item := range state.Entries {
		if item.Reference == reference {
			index = current
			break
		}
	}
	if index < 0 {
		return ErrEntryNotFound
	}

	remaining := metadata{Version: state.Version, Entries: make([]entry, 0, len(state.Entries)-1)}
	remaining.Entries = append(remaining.Entries, state.Entries[:index]...)
	remaining.Entries = append(remaining.Entries, state.Entries[index+1:]...)
	if err := store.writeMetadata(remaining); err != nil {
		return err
	}

	valuePath := filepath.Join(store.root, "values", state.Entries[index].Identifier)
	if err := os.Remove(valuePath); err != nil {
		if reconcileErr := store.reconcileMetadata(state); reconcileErr != nil {
			return reconcileErr
		}
		return err
	}
	if err := syncDirectory(filepath.Dir(valuePath)); err != nil {
		return err
	}
	return nil
}

// ClearAll removes every Cache Entry after validating complete cache state.
func (store Store) ClearAll() error {
	return store.ClearAllContext(context.Background())
}

// ClearAllContext is ClearAll with a cancellation-aware lock acquisition.
func (store Store) ClearAllContext(ctx context.Context) error {
	return store.clearAllContext(ctx, os.Remove)
}

// clearAll accepts the removal operation separately so partial-removal recovery
// can be exercised without changing process-wide filesystem behavior.
func (store Store) clearAll(remove func(string) error) error {
	return store.clearAllContext(context.Background(), remove)
}

func (store Store) clearAllContext(ctx context.Context, remove func(string) error) error {
	lock, exists, err := store.acquireLock(ctx, true)
	if err != nil || !exists {
		return err
	}
	defer releaseLock(lock)

	state, err := store.readValidatedMetadata()
	if err != nil {
		return err
	}
	if len(state.Entries) == 0 {
		return nil
	}

	entries := append([]entry(nil), state.Entries...)
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Reference < entries[right].Reference
	})
	for _, item := range entries {
		if err := remove(filepath.Join(store.root, "values", item.Identifier)); err != nil {
			if reconcileErr := store.reconcileMetadata(state); reconcileErr != nil {
				return reconcileErr
			}
			return err
		}
	}
	if err := syncDirectory(filepath.Join(store.root, "values")); err != nil {
		if reconcileErr := store.reconcileMetadata(state); reconcileErr != nil {
			return reconcileErr
		}
		return err
	}

	if err := store.writeMetadata(metadata{Version: schemaVersion, Entries: []entry{}}); err != nil {
		// All value files have already been removed. Keep the index truthful if
		// replacing it fails after the planned removals.
		if reconcileErr := store.reconcileMetadata(state); reconcileErr != nil {
			return reconcileErr
		}
		return err
	}
	return nil
}

// Validate verifies complete existing state before cache state is mutated.
func (store Store) Validate() error {
	return store.ValidateContext(context.Background())
}

// ValidateContext is Validate with a cancellation-aware lock acquisition.
func (store Store) ValidateContext(ctx context.Context) error {
	lock, exists, err := store.acquireLock(ctx, false)
	if err != nil || !exists {
		return err
	}
	defer releaseLock(lock)
	return store.validateUnlocked()
}

// ValidateEntry verifies complete cache state and reports whether reference is indexed.
func (store Store) ValidateEntry(reference string) (bool, error) {
	return store.ValidateEntryContext(context.Background(), reference)
}

// ValidateEntryContext is ValidateEntry with a cancellation-aware lock acquisition.
func (store Store) ValidateEntryContext(ctx context.Context, reference string) (bool, error) {
	lock, exists, err := store.acquireLock(ctx, false)
	if err != nil || !exists {
		return false, err
	}
	defer releaseLock(lock)

	state, err := store.readValidatedMetadata()
	if err != nil {
		return false, err
	}
	return hasEntry(state, reference), nil
}

func hasEntry(state metadata, reference string) bool {
	for _, item := range state.Entries {
		if item.Reference == reference {
			return true
		}
	}
	return false
}

func (store Store) validateUnlocked() error {
	_, err := store.readValidatedMetadata()
	return err
}

func (store Store) readValidatedMetadata() (metadata, error) {
	state, exists, err := store.readMetadata()
	if err != nil || !exists {
		return state, err
	}
	if err := store.validateValues(state); err != nil {
		return metadata{}, err
	}
	return state, nil
}

func (store Store) reconcileMetadata(state metadata) error {
	remaining := metadata{Version: state.Version, Entries: make([]entry, 0, len(state.Entries))}
	for _, item := range state.Entries {
		path := filepath.Join(store.root, "values", item.Identifier)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || validateInfo(info, false) != nil || info.Size() > MaximumSecretValueSize {
			return ErrInvalidState
		}
		remaining.Entries = append(remaining.Entries, item)
	}
	return store.writeMetadata(remaining)
}

func (store Store) validateValues(state metadata) error {
	expected := make(map[string]struct{}, len(state.Entries))
	for _, item := range state.Entries {
		expected[item.Identifier] = struct{}{}
		if err := validateValueNode(filepath.Join(store.root, "values", item.Identifier)); err != nil {
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
		if err := validateValueNode(filepath.Join(store.root, "values", file.Name())); err != nil {
			return ErrInvalidState
		}
	}
	return nil
}

// Put atomically replaces the individual value and metadata files for a successful retrieval.
func (store Store) Put(reference string, value []byte, cachedAt time.Time) error {
	return store.PutContext(context.Background(), reference, value, cachedAt)
}

// PutContext is Put with a cancellation-aware lock acquisition.
func (store Store) PutContext(ctx context.Context, reference string, value []byte, cachedAt time.Time) error {
	if len(value) > MaximumSecretValueSize {
		return ErrInvalidState
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := store.ensureLayout(); err != nil {
		return err
	}

	lock, exists, err := store.acquireLock(ctx, true)
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidState
	}
	defer releaseLock(lock)
	if err := contextError(ctx); err != nil {
		return err
	}

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

	return store.writeMetadata(state)
}

// Revalidate replaces an existing Cache Entry after the new Secret Value has
// been retrieved successfully. It never creates a missing Cache Entry.
func (store Store) Revalidate(reference string, value []byte, cachedAt time.Time) error {
	return store.RevalidateContext(context.Background(), reference, value, cachedAt)
}

// RevalidateContext is Revalidate with a cancellation-aware lock acquisition.
func (store Store) RevalidateContext(ctx context.Context, reference string, value []byte, cachedAt time.Time) error {
	return store.revalidateWithContext(ctx, reference, value, cachedAt, store.renameAndSync)
}

// revalidate accepts the rename operation separately so commit rollback can be
// exercised without changing process-wide filesystem behavior.
func (store Store) revalidate(reference string, value []byte, cachedAt time.Time, rename func(string, string) error) error {
	return store.revalidateWithContext(context.Background(), reference, value, cachedAt, rename)
}

func (store Store) revalidateWithContext(ctx context.Context, reference string, value []byte, cachedAt time.Time, rename func(string, string) error) error {
	if len(value) > MaximumSecretValueSize {
		return ErrInvalidState
	}

	lock, exists, err := store.acquireLock(ctx, true)
	if err != nil {
		return err
	}
	if !exists {
		return ErrEntryNotFound
	}
	defer releaseLock(lock)
	if err := contextError(ctx); err != nil {
		return err
	}

	state, err := store.readValidatedMetadata()
	if err != nil {
		return err
	}
	index := -1
	for current, item := range state.Entries {
		if item.Reference == reference {
			index = current
			break
		}
	}
	if index < 0 {
		return ErrEntryNotFound
	}

	valuePath := filepath.Join(store.root, "values", state.Entries[index].Identifier)
	previousValue, err := os.ReadFile(valuePath)
	if err != nil {
		return ErrInvalidState
	}

	replacement := metadata{Version: state.Version, Entries: append([]entry(nil), state.Entries...)}
	replacement.Entries[index].CachedAt = cachedAt.UTC().Truncate(time.Second).Format(time.RFC3339)

	valueTemporary, err := prepareAtomicWrite(valuePath, value)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(valueTemporary) }()

	content, err := metadataBytes(replacement)
	if err != nil {
		return err
	}
	metadataTemporary, err := prepareAtomicWrite(filepath.Join(store.root, "metadata.json"), content)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(metadataTemporary) }()

	if err := rename(valueTemporary, valuePath); err != nil {
		return err
	}
	if err := rename(metadataTemporary, filepath.Join(store.root, "metadata.json")); err != nil {
		if restoreErr := atomicWrite(valuePath, previousValue); restoreErr != nil {
			return ErrInvalidState
		}
		return err
	}
	return nil
}

func (store Store) writeMetadata(state metadata) error {
	content, err := metadataBytes(state)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(store.root, "metadata.json"), content)
}

func (store Store) renameAndSync(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(newPath))
}

func metadataBytes(state metadata) ([]byte, error) {
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
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

func (store Store) acquireLock(ctx context.Context, exclusive bool) (*os.File, bool, error) {
	ctx = contextOrBackground(ctx)
	if err := contextError(ctx); err != nil {
		return nil, false, err
	}
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
	if err != nil || validateInfo(info, false) != nil {
		_ = lock.Close()
		return nil, false, ErrInvalidState
	}

	for {
		locked, err := tryLockFile(lock, exclusive)
		if err != nil {
			_ = lock.Close()
			return nil, false, ErrInvalidState
		}
		if locked {
			if err := contextError(ctx); err != nil {
				_ = unlockFile(lock)
				_ = lock.Close()
				return nil, false, err
			}
			return lock, true, nil
		}

		timer := time.NewTimer(lockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = lock.Close()
			return nil, false, ctx.Err()
		case <-timer.C:
		}
	}
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
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
	if err != nil || !utf8.Valid(content) {
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
		if !validSecretReference(item.Reference) || item.Identifier != Identifier(item.Reference) || !validTimestamp(item.CachedAt) {
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

func validateValueNode(path string) error {
	info, err := os.Lstat(path)
	if err != nil || validateInfo(info, false) != nil || info.Size() > MaximumSecretValueSize {
		return ErrInvalidState
	}
	return nil
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

	if info, err := os.Lstat(store.root); err == nil {
		if validateInfo(info, true) != nil {
			return ErrInvalidState
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidState
	}

	// Build a complete empty cache privately so no process can observe partial
	// metadata while the cache lock is being initialized.
	temporary, err := os.MkdirTemp(filepath.Dir(store.root), ".temporary-cache-*")
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, directoryMode); err != nil {
		return err
	}
	if err := makePrivateDirectory(filepath.Join(temporary, "values")); err != nil {
		return err
	}

	lockPath := filepath.Join(temporary, "cache.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, regularFileMode)
	if err != nil {
		return err
	}
	if err := lock.Chmod(regularFileMode); err != nil {
		_ = lock.Close()
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}

	content, err := metadataBytes(metadata{Version: schemaVersion, Entries: []entry{}})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(temporary, "metadata.json"), content); err != nil {
		return err
	}
	if err := syncDirectory(temporary); err != nil {
		return err
	}

	if err := os.Rename(temporary, store.root); err != nil {
		if _, statErr := os.Lstat(store.root); statErr != nil {
			return err
		}
		return nil
	}
	removeTemporary = false
	return syncDirectory(filepath.Dir(store.root))
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
	temporaryPath, err := prepareAtomicWrite(path, content)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func prepareAtomicWrite(path string, content []byte) (string, error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".temporary-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(regularFileMode); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if written, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return "", err
	} else if written != len(content) {
		_ = temporary.Close()
		return "", io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return temporaryPath, nil
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339) == value
}
