# Store Cache Entries without application encryption

Store Secret Values as plaintext protected by owner-only filesystem access rather than application-level encryption. Unattended shell startup must not require another key or authentication step, so the security boundary is the user's operating-system account and disk encryption; this does not protect values from root, a compromised user account, filesystem snapshots, backups, or offline copies.
