# Postgres Storage Backend Evaluation

## 1. Overview
This document evaluates the architectural requirements for transitioning the RGT-Vault storage backend from SQLite to PostgreSQL. The primary motivation is to support multi-process, distributed deployments where a single file-based SQLite database becomes a concurrency bottleneck or deployment constraint.

## 2. SQLite-Specific Features and Postgres Equivalents

The current `StorageBackend` relies heavily on SQLite-specific behaviors. Moving to Postgres requires adapting these mechanisms:

| Feature | Current SQLite Implementation | Postgres Equivalent |
| :--- | :--- | :--- |
| **WAL (Write-Ahead Logging)** | `PRAGMA journal_mode = WAL` enables concurrent readers and a single writer. | **Native MVCC** (Multi-Version Concurrency Control). Postgres inherently supports concurrent readers without blocking writers. |
| **JSON1 Extension** | Manipulating and querying JSON in text columns. | **JSONB Data Type**. Postgres provides native, highly-optimized `jsonb` columns with rich indexing (GIN) and operators. |
| **FTS (Full Text Search)** | SQLite FTS5 virtual tables for fast text searching. | **tsvector / tsquery**. Postgres provides native full-text search capabilities using GIN indices on `tsvector` columns. |
| **Foreign Keys (FK)** | `PRAGMA foreign_keys = ON` at the connection level. | **Native Table Constraints**. Foreign keys are enforced strictly at the schema level by default. |

## 3. Transaction Semantics

### SQLite (`BEGIN IMMEDIATE`)
The vault heavily uses `BEGIN IMMEDIATE` to acquire an exclusive write lock across the entire database before reading. This ensures that read-modify-write cycles (like updating the audit log hash chain) do not fork.

### Postgres Equivalents
Postgres does not lock the entire database on writes. To achieve the same linearizable guarantee for the audit chain:
1. **Row-Level Locking:** Use `SELECT ... FOR UPDATE` when fetching the previous audit log hash. This locks the specific row against concurrent modifications.
2. **Serialization Isolation:** Run the transaction with `SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;` to ensure strict serializability, though this may result in serialization failures requiring application-level retries.
3. **Table Locks:** If absolute serialization across a table is required, `LOCK TABLE audit_logs IN EXCLUSIVE MODE` can emulate SQLite's behavior, though it reduces concurrency.

## 4. Connection Pooling

- **SQLite:** Currently uses single connections instantiated per request, or simple thread-local connections.
- **Postgres:** Multi-process deployments will exhaust connections quickly if not pooled. The backend must implement connection pooling using `psycopg2.pool.ThreadedConnectionPool` in-process, or rely on an external pooler like **PgBouncer** in transaction mode.

## 5. Conclusion
Migrating to Postgres is highly feasible and unlocks horizontal scalability. The main engineering effort lies in replacing `BEGIN IMMEDIATE` DB-level locks with explicit `SELECT ... FOR UPDATE` row-level locks to preserve the strict integrity of the audit hash chain.
