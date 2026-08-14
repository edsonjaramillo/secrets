# Use a permanent, manually managed cache

Cache Entries do not expire and a cache hit does not contact 1Password; they remain authoritative until explicitly cleared or revalidated. This accepts stale Secret Values and places freshness under user control because fast, authentication-free shell startup and offline availability take priority over automatic freshness checks.
