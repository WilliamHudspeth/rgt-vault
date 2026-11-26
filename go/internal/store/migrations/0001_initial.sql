CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    checksum TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_current INTEGER DEFAULT 1,
    UNIQUE(name, version)
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    secret_name TEXT,
    timestamp TEXT NOT NULL,
    details TEXT,
    prev_hash TEXT DEFAULT '',
    entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS honeytokens (
    name TEXT NOT NULL PRIMARY KEY
);
