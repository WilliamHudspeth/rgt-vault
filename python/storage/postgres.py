import hashlib
from typing import Optional, Tuple
import psycopg2
from psycopg2.pool import ThreadedConnectionPool

from rgt_vault.exceptions import ChecksumError

class PostgresStorageBackendPoC:
    """
    Read-only Proof of Concept for a Postgres storage backend.
    Demonstrates connection pooling and a basic get_secret flow.
    """
    def __init__(self, dsn: str):
        # 1. Connection Pooling
        # In a multi-process/multi-thread environment, a connection pool is required.
        self.pool = ThreadedConnectionPool(minconn=1, maxconn=10, dsn=dsn)

    def get_secret(self, namespace: str, name: str, version: Optional[int] = None) -> Optional[Tuple[bytes, int]]:
        """
        Retrieves a secret. Demonstrates row-level locking equivalents if this were a write,
        but for read-only PoC, it's a standard SELECT.
        """
        conn = self.pool.getconn()
        try:
            with conn.cursor() as cursor:
                # 2. Transaction Semantics (Read)
                # In Postgres, we don't need BEGIN IMMEDIATE. 
                # If we were writing/auditing here (like SQLite does), we would use SELECT ... FOR UPDATE on the audit log.
                
                if version is not None:
                    cursor.execute(
                        \"\"\"
                        SELECT ciphertext, checksum, dek_version FROM secrets
                        WHERE namespace = %s AND name = %s AND version = %s
                        \"\"\",
                        (namespace, name, version),
                    )
                else:
                    cursor.execute(
                        \"\"\"
                        SELECT ciphertext, checksum, dek_version FROM secrets
                        WHERE namespace = %s AND name = %s AND status = 'ACTIVE'
                        ORDER BY version DESC LIMIT 1
                        \"\"\",
                        (namespace, name),
                    )

                row = cursor.fetchone()

                if row:
                    ciphertext, checksum, dek_version = row
                    
                    # Convert psycopg2 memoryview/bytes to raw bytes
                    if isinstance(ciphertext, memoryview):
                        ciphertext = ciphertext.tobytes()

                    if hashlib.sha256(ciphertext).hexdigest() != checksum:
                        raise ChecksumError(f"Integrity check failed for secret '{namespace}/{name}'")

                    return ciphertext, dek_version

                return None
        finally:
            self.pool.putconn(conn)
