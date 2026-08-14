# Secrets

A command-line context for retrieving 1Password secrets and retaining explicitly managed local copies for fast, non-interactive reuse.

## Language

**Secret Reference**:
A valid 1Password secret reference beginning with `op://` that identifies a value without containing the value itself.
_Avoid_: Secret name, path, key

**Secret Value**:
The confidential, opaque byte sequence resolved from a Secret Reference. It must never be altered or appear in logs, errors, status output, or cache listings.
_Avoid_: Credential, password, token

**Cache Entry**:
A locally persisted Secret Value identified by a hash of the exact, complete Secret Reference string and retained until explicitly cleared or revalidated. Textually different references always identify different Cache Entries.
_Avoid_: Cached secret, cache file

**Revalidation**:
The explicit replacement of an existing Cache Entry with the current Secret Value resolved from the same Secret Reference. It never creates a missing Cache Entry.
_Avoid_: Refresh, update, verification
