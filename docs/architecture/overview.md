# Architecture Overview

RGT Vault separates the **capability execution model** from the underlying **secure secret storage**.

This layered approach ensures that agents only receive the capabilities they are authorized to use, while the highly sensitive secret material is protected by a robust cryptographic key hierarchy.

*   **[Execution Flow](execution-flow.md):** How the Vault intercepts requests, verifies tokens, and executes capabilities.
*   **[Cryptography](crypto.md):** How the Vault secures data at rest using AES-GCM, Argon2id, and OS-native keychain APIs.
