# Store Secret References as protected metadata

Cache management requires recovering Secret References for listing, bulk revalidation, and shell completion, but hashing references for value filenames makes them otherwise unrecoverable. Store full Secret References in a plaintext metadata index protected by owner-only filesystem permissions; accept that administrative output and completion expose this sensitive metadata, while keeping Secret Values hash-addressed, out of the index, and absent from all administrative output.
