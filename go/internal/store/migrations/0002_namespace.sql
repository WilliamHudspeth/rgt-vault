-- P2-6 audit fix: connection-level PRAGMAs (foreign_keys, journal_mode,
-- synchronous) belong in the storage layer's per-connection setup, not in
-- migration files. Migrations must be portable SQL that any future
-- storage backend (Postgres etc.) can execute without SQLite-specific
-- side effects. The previous version wrapped the body in
-- ``PRAGMA foreign_keys=off; BEGIN; ...; COMMIT; PRAGMA foreign_keys=on;``
-- which is unnecessary because the schema currently declares no foreign
-- keys and the storage layer sets ``PRAGMA foreign_keys=ON`` per
-- connection anyway.

BEGIN TRANSACTION;

CREATE TABLE secrets_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    checksum TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    UNIQUE(namespace, name, version)
);

INSERT INTO secrets_new (id, secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status)
SELECT id,
       lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6))),
       'default', name, version, ciphertext, checksum, created_at, updated_at,
       CASE WHEN is_current = 1 THEN 'ACTIVE' ELSE 'SUPERSEDED' END
FROM secrets;

DROP TABLE secrets;
ALTER TABLE secrets_new RENAME TO secrets;

CREATE TABLE honeytokens_new (
    namespace TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    PRIMARY KEY(namespace, name)
);

INSERT INTO honeytokens_new (namespace, name)
SELECT 'default', name FROM honeytokens;

DROP TABLE honeytokens;
ALTER TABLE honeytokens_new RENAME TO honeytokens;

ALTER TABLE audit_logs ADD COLUMN policy_hash TEXT;

COMMIT;