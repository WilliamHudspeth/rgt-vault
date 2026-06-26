# Threat Modeling and Mitigation Inventory

Comprehensive catalog of threats and design flaws identified through threat modeling using STRIDE methodology. Includes threat description, assessment, and implemented mitigations.

---

## Threat Model Scope

**System Components**:
- Client applications (CLI, API clients)
- API Gateway/Server
- Vault Backend Core (secret storage, retrieval, management)
- Encryption/Cryptographic Layer
- Authentication/Authorization Layer
- Database Storage Layer
- Configuration and Key Management Layer
- Audit Logging System

**Trust Boundaries**:
- Network boundary (untrusted network to secure server)
- Authentication boundary (unauthenticated to authenticated users)
- Authorization boundary (restricted access by role/permission)
- Encryption boundary (plaintext to ciphertext)

**Data Flows**:
- Client → Server: API requests (Create, Read, Update, Delete secrets)
- Server → Database: Storage operations
- Encryption Service: Key management, encryption/decryption
- Audit System: Logging of access and modifications

---

## Threat Categories

Threats organized by STRIDE framework:
- **Spoofing**: Identity spoofing, impersonation, credential theft
- **Tampering**: Unauthorized modification, man-in-the-middle attacks
- **Repudiation**: Denial of actions, inability to prove what happened
- **Information Disclosure**: Exposure of secrets, configuration, metadata
- **Denial of Service**: Resource exhaustion, availability attacks
- **Elevation of Privilege**: Unauthorized escalation, privilege creep

---

## S - SPOOFING THREATS

### T-SPOOF-001: Authentication Bypass

**Description**: Attacker attempts to bypass authentication mechanisms to access vault without valid credentials.

**Attack Vector**: 
- Exploit weak authentication (no MFA, weak password)
- Session token theft or forgery
- Credential reuse from other systems
- Authentication logic bugs

**CVSS Severity**: 9.1 (Critical)

**Affected Components**:
- Authentication layer
- Session management
- API endpoint protection

**Mitigations**:
1. **Preventive**:
   - Multi-factor authentication (MFA) support
   - Strong password requirements (minimum 12 characters, complexity)
   - Secure session management (random tokens, HTTPS-only cookies)
   - Session timeout (reasonable, context-dependent)
   - Rate limiting on authentication attempts

2. **Detective**:
   - Failed authentication attempt logging
   - Unusual access pattern detection
   - Geographic anomaly detection (if applicable)
   - Brute force attack monitoring

3. **Corrective**:
   - Account lockout after failed attempts (5 failures = 15 minute lockout)
   - Forced password reset capability
   - Session invalidation procedures
   - Incident response procedures

**Status**: Implemented - Authentication controls in place
**Last Review**: 2026-06-26
**Evidence**: Source code review, authentication testing, security testing

---

### T-SPOOF-002: Credential Theft

**Description**: Attacker steals valid credentials through phishing, malware, or insecure storage.

**Attack Vector**:
- Credentials transmitted in plaintext
- Credentials stored insecurely (local files, browser cache)
- Phishing emails directing to fake login page
- Malware capturing keystrokes
- Credential databases leaked

**CVSS Severity**: 8.8 (High)

**Affected Components**:
- Credential storage
- Transmission channels
- Client applications

**Mitigations**:
1. **Preventive**:
   - TLS encryption for all credential transmission
   - Credentials never logged or displayed (masking in logs)
   - Secure credential storage (never plaintext in memory)
   - Credential rotation guidance
   - Zero-trust security approach

2. **Detective**:
   - Monitoring for credential use from unusual locations/times
   - Failed authentication from same IP after credentials used elsewhere
   - Audit logging of credential changes
   - Impossible travel detection (if applicable)

3. **Corrective**:
   - Rapid credential revocation capability
   - Credential compromise response procedures
   - Communication to affected users
   - Force password reset

**Status**: Implemented - Encryption and secure handling
**Last Review**: 2026-06-26
**Evidence**: Code review of credential handling, TLS configuration

---

### T-SPOOF-003: Man-in-the-Middle (MITM) Attack

**Description**: Attacker intercepts communications between client and server to impersonate either party.

**Attack Vector**:
- Weak TLS configuration (downgrade to HTTP)
- Certificate validation bypass
- Rogue certificate authority
- DNS hijacking
- Insecure network (open WiFi)

**CVSS Severity**: 8.1 (High)

**Affected Components**:
- Network communications
- TLS/SSL implementation
- Certificate validation

**Mitigations**:
1. **Preventive**:
   - TLS 1.2+ mandatory (TLS 1.3 preferred)
   - Certificate pinning for critical connections
   - Strong cipher suites only (no weak ciphers)
   - HSTS (HTTP Strict-Transport-Security)
   - Certificate validation enforcement (no exceptions)

2. **Detective**:
   - TLS handshake failure logging
   - Certificate validation failure monitoring
   - Unusual TLS errors tracking

3. **Corrective**:
   - Connection failure procedures
   - Incident investigation capabilities
   - User notification of connection issues

**Status**: Implemented - TLS 1.2+ enforcement, certificate validation
**Last Review**: 2026-06-26
**Evidence**: Network configuration, TLS testing, security scanning

---

## T - TAMPERING THREATS

### T-TAMP-001: Unauthorized Secret Modification

**Description**: Attacker modifies vault secrets without authorization.

**Attack Vector**:
- Exploiting authorization vulnerability
- SQL injection in database operations
- Compromise of database credentials
- Malicious insider access
- API logic bugs

**CVSS Severity**: 9.0 (Critical)

**Affected Components**:
- Authorization layer
- Secret storage/modification logic
- Database access controls
- API endpoints

**Mitigations**:
1. **Preventive**:
   - Role-based access control (RBAC)
   - Principle of least privilege enforcement
   - Input validation and parameterized queries (SQL injection prevention)
   - Strong authorization checks before modification
   - API rate limiting to detect bulk modifications

2. **Detective**:
   - Audit logging of all secret modifications
   - Change detection (hash verification)
   - Anomaly detection (bulk changes, out-of-hours access)
   - Integrity verification checks

3. **Corrective**:
   - Secret versioning (maintain history)
   - Rollback capabilities
   - Audit trail for forensics
   - Incident response procedures

**Status**: Implemented - RBAC, audit logging, input validation
**Last Review**: 2026-06-26
**Evidence**: Code review, architecture review, security testing

---

### T-TAMP-002: Code Injection Attacks

**Description**: Attacker injects malicious code through various injection vectors.

**Attack Vectors**:
- SQL Injection: Malicious SQL in input parameters
- Command Injection: OS command execution through unsanitized input
- LDAP Injection: LDAP query manipulation
- XML/XXE Injection: XML parsing vulnerabilities
- Expression Language Injection: Template injection vulnerabilities

**CVSS Severity**: 9.8 (Critical)

**Affected Components**:
- API input handling
- Database query construction
- Configuration parsing
- Integration with external services

**Mitigations**:
1. **Preventive**:
   - Input validation (whitelist approach, length limits, type checking)
   - Parameterized queries/prepared statements
   - Output encoding (context-aware)
   - Disable dangerous features (XXE parsing disabled)
   - Security code review checklist

2. **Detective**:
   - Input validation bypass attempts logged
   - Query injection pattern detection
   - WAF (Web Application Firewall) rules
   - Code scanning tools (SAST)

3. **Corrective**:
   - Request blocking/throttling
   - Incident investigation
   - Code patching procedures

**Status**: Implemented - Input validation, parameterized queries, code review
**Last Review**: 2026-06-26
**Evidence**: SAST scan results, code review records, security testing

---

### T-TAMP-003: Dependency Compromise

**Description**: Attacker compromises third-party dependencies to inject malicious code.

**Attack Vector**:
- Compromised package on PyPI, npm, or other repository
- Supply chain attack on dependency vendor
- Malicious package with similar name (typosquatting)
- Outdated vulnerable dependency not patched
- Compromised build tools or CI/CD system

**CVSS Severity**: 8.6 (High)

**Affected Components**:
- Dependency packages (Python, Go, JavaScript)
- Build pipeline
- CI/CD system
- Package repositories

**Mitigations**:
1. **Preventive**:
   - Dependency pinning (lock files)
   - Checksum verification for dependencies
   - Dependency scanning (OWASP Dependency-Check, Snyk)
   - Regular dependency updates
   - Package authentication (signatures if available)
   - CI/CD security hardening

2. **Detective**:
   - Automated vulnerability scanning
   - Dependency audit tools
   - Build artifact verification
   - Supply chain risk monitoring
   - Suspicious dependency behavior monitoring

3. **Corrective**:
   - Rapid dependency update procedures
   - Rollback to previous safe version
   - Communication to users if compromise detected
   - Forensic analysis of affected builds

**Status**: Implemented - Dependency scanning, lock files, regular updates
**Last Review**: 2026-06-26
**Evidence**: Dependabot scanning, lock files, supply chain monitoring

---

### T-TAMP-004: Configuration Tampering

**Description**: Attacker modifies application configuration to weaken security.

**Attack Vector**:
- Modifying config files on disk
- Environment variable manipulation
- API endpoints for configuration (if exposed)
- Privilege escalation to modify configs
- Compromised deployment pipeline

**CVSS Severity**: 7.5 (High)

**Affected Components**:
- Configuration files
- Environment variable handling
- Configuration management
- Deployment pipeline

**Mitigations**:
1. **Preventive**:
   - Configuration access control (file permissions, restricted access)
   - Configuration validation on startup
   - Cryptographic signing of configuration (if possible)
   - Secure defaults (not relying on config for security)
   - Immutable infrastructure approach

2. **Detective**:
   - Configuration file integrity monitoring
   - Change detection and logging
   - Startup validation failure alerts
   - Configuration audit logs

3. **Corrective**:
   - Configuration rollback procedures
   - Service restart procedures
   - Incident response

**Status**: Implemented - File permissions, validation, secure defaults
**Last Review**: 2026-06-26
**Evidence**: Deployment procedures, configuration validation code

---

## R - REPUDIATION THREATS

### T-REP-001: Denial of Actions

**Description**: Attacker performs actions but denies having done so; lack of audit trail for accountability.

**Attack Vector**:
- Insufficient logging
- Editable or deletable logs
- Lack of timestamps
- Inability to prove who performed actions
- Batch operations without individual attribution

**CVSS Severity**: 6.5 (Medium)

**Affected Components**:
- Audit logging system
- Log storage
- Log access controls

**Mitigations**:
1. **Preventive**:
   - Comprehensive audit logging (all security-relevant events)
   - User identification (who performed action)
   - Timestamp logging (when action occurred)
   - Action description (what action occurred)
   - Immutable log storage (append-only)
   - Log encryption (confidentiality and integrity)

2. **Detective**:
   - Log integrity verification
   - Audit log review procedures
   - Log tampering detection
   - Unauthorized log access detection

3. **Corrective**:
   - Incident investigation procedures
   - Forensic analysis capabilities
   - Log recovery from backups

**Status**: Implemented - Comprehensive audit logging, immutable logs
**Last Review**: 2026-06-26
**Evidence**: Audit logging code, log retention policies, log access controls

---

## I - INFORMATION DISCLOSURE THREATS

### T-INFO-001: Secret Exposure via Logs

**Description**: Secrets accidentally exposed in application logs or debug output.

**Attack Vector**:
- Logging secret values
- Logging error messages containing secrets
- Debug mode leaving secrets in output
- Verbose logging in production
- Log aggregation systems exposing secrets

**CVSS Severity**: 7.5 (High)

**Affected Components**:
- Logging system
- Error handling
- Debug output
- Log aggregation

**Mitigations**:
1. **Preventive**:
   - Never log secret values (masked logging)
   - Input validation preventing secrets in error messages
   - Redaction filters on logging (automatic masking)
   - Debug mode disabled in production
   - Structured logging with field-level control

2. **Detective**:
   - Log review for accidental secrets
   - Automated secret scanning in logs
   - Secret pattern detection (regex-based)
   - Log audit trails

3. **Corrective**:
   - Log purge procedures for exposed logs
   - Secret rotation if exposed
   - Incident response

**Status**: Implemented - Logging safeguards, masking, redaction filters
**Last Review**: 2026-06-26
**Evidence**: Code review of logging, log redaction configuration

---

### T-INFO-002: Database Exposure

**Description**: Unauthorized access to database exposes all stored secrets.

**Attack Vector**:
- Database credentials exposed
- SQL injection bypassing access controls
- Database server misconfiguration
- Backup file exposure
- Privilege escalation to database access

**CVSS Severity**: 10.0 (Critical)

**Affected Components**:
- Database server
- Database credentials
- Database backups
- Database access controls

**Mitigations**:
1. **Preventive**:
   - Strong database credentials (unique, complex passwords)
   - Database encryption at rest (AES-256)
   - Network isolation (database not directly accessible)
   - Principle of least privilege (restricted database user)
   - Firewall rules restricting database access
   - Input validation preventing SQL injection

2. **Detective**:
   - Database access monitoring
   - Unusual query patterns
   - Failed access attempts logging
   - Data access audit trails
   - Backup integrity monitoring

3. **Corrective**:
   - Database access revocation
   - Encryption key rotation
   - Affected secrets notification
   - Incident response procedures

**Status**: Implemented - Encryption, access control, network isolation
**Last Review**: 2026-06-26
**Evidence**: Database configuration, encryption implementation, access controls

---

### T-INFO-003: Metadata Exposure

**Description**: Sensitive metadata (API responses, error messages, headers) exposes system information.

**Attack Vector**:
- Verbose error messages revealing stack traces
- HTTP headers exposing software versions
- API responses containing unnecessary information
- Directory listing enabled
- Comments in HTML/JavaScript exposing paths

**CVSS Severity**: 5.3 (Medium)

**Affected Components**:
- API responses
- Error handling
- HTTP headers
- Web server configuration

**Mitigations**:
1. **Preventive**:
   - Generic error messages (not exposing internals)
   - Remove version information from headers
   - Minimal API response payloads (only necessary data)
   - Disable directory listing
   - Remove debugging comments from production code

2. **Detective**:
   - Error message review
   - Header analysis
   - API response auditing
   - Vulnerability scanning

3. **Corrective**:
   - Configuration changes
   - Code updates to remove information disclosure
   - Incident investigation

**Status**: Implemented - Generic error messages, minimal responses
**Last Review**: 2026-06-26
**Evidence**: Code review, API testing, security scanning

---

### T-INFO-004: Backup and Archive Exposure

**Description**: Backups or archived versions expose historical secrets.

**Attack Vector**:
- Unencrypted backups
- Backup storage accessible without authentication
- Archived versions with different secrets
- Backup retention too long
- Backup disaster recovery not tested

**CVSS Severity**: 8.2 (High)

**Affected Components**:
- Backup system
- Archive storage
- Backup encryption
- Backup access controls

**Mitigations**:
1. **Preventive**:
   - Backup encryption (same as production)
   - Backup access control (restricted to authorized personnel)
   - Backup storage isolation (separate system)
   - Backup retention policies (data deleted when no longer needed)
   - Backup verification procedures

2. **Detective**:
   - Backup integrity monitoring
   - Backup access logging
   - Unauthorized access detection
   - Backup enumeration attempts

3. **Corrective**:
   - Backup isolation/deletion procedures
   - Secret rotation if compromised
   - Incident response

**Status**: Implemented - Encrypted backups, access control, retention policies
**Last Review**: 2026-06-26
**Evidence**: Backup procedures, encryption implementation, access controls

---

## D - DENIAL OF SERVICE THREATS

### T-DOS-001: Resource Exhaustion

**Description**: Attacker exhausts server resources (CPU, memory, disk, connections) causing unavailability.

**Attack Vector**:
- Request flooding (HTTP flood, API request spam)
- Large payload attacks
- Algorithmic complexity attacks (causing CPU exhaustion)
- Memory exhaustion (large secrets, bulk operations)
- Disk exhaustion (logging, storage)
- Connection exhaustion

**CVSS Severity**: 7.5 (High)

**Affected Components**:
- API server
- Database
- Storage system
- Network infrastructure

**Mitigations**:
1. **Preventive**:
   - Rate limiting (requests per IP/user, time-based)
   - Request timeout (prevent long-running requests)
   - Input size limits (payload size, secret size)
   - Connection pooling (limit concurrent connections)
   - Resource monitoring and alerting
   - Efficient algorithms (prevent algorithmic complexity attacks)
   - Load balancing (distribute load across servers)

2. **Detective**:
   - Resource usage monitoring
   - Request pattern analysis
   - Anomaly detection (unusual traffic volumes)
   - Alert on resource thresholds
   - DDoS detection systems

3. **Corrective**:
   - Request throttling/blocking
   - Service degradation (reduce features under load)
   - Scale up resources (auto-scaling if applicable)
   - Incident response procedures

**Status**: Implemented - Rate limiting, timeouts, input validation
**Last Review**: 2026-06-26
**Evidence**: Rate limiting configuration, timeout settings, resource monitoring

---

### T-DOS-002: Application Crash

**Description**: Attacker causes application to crash through malformed input or logic bugs.

**Attack Vector**:
- Null pointer dereference
- Array out-of-bounds access
- Unhandled exceptions
- Infinite loops
- Stack overflow
- Division by zero

**CVSS Severity**: 7.5 (High)

**Affected Components**:
- API server
- Application logic
- Error handling

**Mitigations**:
1. **Preventive**:
   - Input validation (prevent invalid states)
   - Bounds checking (array access validation)
   - Exception handling (catch and recover)
   - Code review focusing on edge cases
   - Unit testing of error conditions
   - Defensive programming practices

2. **Detective**:
   - Crash logging and alerting
   - Exception tracking
   - Monitoring for service restarts
   - Log analysis for error patterns

3. **Corrective**:
   - Automatic service restart
   - Error notification procedures
   - Bug fix procedures
   - Post-mortem analysis

**Status**: Implemented - Exception handling, input validation, testing
**Last Review**: 2026-06-26
**Evidence**: Code review, exception handling code, test coverage

---

## E - ELEVATION OF PRIVILEGE THREATS

### T-ELEV-001: Authorization Bypass

**Description**: Attacker gains access to resources or operations they're not authorized for.

**Attack Vector**:
- Authorization logic bugs
- Missing authorization checks
- Privilege escalation in code
- Bypass of role-based access control
- Session fixation allowing assumption of higher privilege
- API endpoints with missing authorization

**CVSS Severity**: 9.1 (Critical)

**Affected Components**:
- Authorization layer
- API endpoints
- Role-based access control
- Session management

**Mitigations**:
1. **Preventive**:
   - Authorization checks on all protected operations
   - Role-based access control (RBAC) enforcement
   - Principle of least privilege (default deny)
   - Authorization caching (with proper TTL)
   - Positive authorization (check for permission, not absence of denial)
   - Code review focusing on authorization

2. **Detective**:
   - Audit logging of authorization checks
   - Failed authorization attempt tracking
   - Anomaly detection (privilege escalation patterns)
   - Access review and validation

3. **Corrective**:
   - Access revocation procedures
   - Incident investigation
   - Remediation and patching
   - User notification

**Status**: Implemented - RBAC, authorization checks, code review
**Last Review**: 2026-06-26
**Evidence**: Authorization implementation code, code review records, testing

---

### T-ELEV-002: Insecure Direct Object References (IDOR)

**Description**: Attacker accesses resources belonging to other users by manipulating reference IDs.

**Attack Vector**:
- Predictable object IDs (sequential numbers)
- User IDs or resource IDs exposed in URLs/parameters
- Missing authorization checks on object access
- Trusting user input for object ownership

**CVSS Severity**: 7.1 (High)

**Affected Components**:
- API endpoints
- Authorization layer
- Object reference handling

**Mitigations**:
1. **Preventive**:
   - Non-predictable object IDs (UUIDs instead of sequential)
   - Authorization check before accessing any object (verify ownership)
   - Not exposing internal IDs unnecessarily
   - Input validation on object references
   - Principle of least privilege (default deny)

2. **Detective**:
   - Access attempts to objects not owned
   - Audit logging of object access
   - Anomaly detection (access pattern changes)
   - API access monitoring

3. **Corrective**:
   - Access blocking/revocation
   - Incident investigation
   - Remediation procedures

**Status**: Implemented - UUID usage, authorization checks, access logging
**Last Review**: 2026-06-26
**Evidence**: API implementation, ID generation, authorization code

---

### T-ELEV-003: Privilege Escalation via Roles

**Description**: Attacker escalates privileges by exploiting role management or group membership.

**Attack Vector**:
- Modifying user roles (if not properly controlled)
- Group membership manipulation
- Default admin accounts not changed
- Shared accounts with higher privileges
- Privilege inheritance bugs

**CVSS Severity**: 8.8 (High)

**Affected Components**:
- User management
- Role management
- Group management
- Access control lists

**Mitigations**:
1. **Preventive**:
   - Access control on role/group modifications (admin-only)
   - Audit logging of role changes
   - Regular role review and validation
   - Separation of duties (role changes require approval)
   - Default admin accounts changed on first deployment

2. **Detective**:
   - Role change monitoring and alerts
   - Privilege escalation pattern detection
   - Access review procedures
   - Suspicious role activity investigation

3. **Corrective**:
   - Role revocation procedures
   - Incident investigation
   - Access audit
   - Remediation and patching

**Status**: Implemented - Role-based access control, audit logging
**Last Review**: 2026-06-26
**Evidence**: Role management code, audit logging, access controls

---

## Design Flaws

### DF-001: Cryptographic Weakness

**Description**: Design flaw in cryptographic implementation or algorithm choice.

**Potential Issues**:
- Weak encryption algorithms (DES, MD5)
- Insufficient key length
- Improper key derivation
- Weak random number generation
- Insecure cipher modes
- No authenticated encryption

**Mitigations**:
- Use approved cryptographic algorithms (AES-256-GCM, ChaCha20-Poly1305)
- Minimum 256-bit key length for symmetric encryption
- PBKDF2 for key derivation (10,000+ iterations)
- Cryptographically secure random number generation
- Authenticated encryption (AEAD) for data integrity
- Regular cryptographic review against standards

**Status**: Implemented - Strong cryptography used throughout
**Last Review**: 2026-06-26

---

### DF-002: Missing Input Validation

**Description**: Design assumes input is valid without proper validation.

**Potential Issues**:
- No validation of input length, format, type
- No encoding/escaping of output
- No defense against injection attacks
- Assumption of trusted input

**Mitigations**:
- Whitelist-based input validation
- Length limits enforced
- Type checking on inputs
- Output encoding and escaping
- Parameterized queries for database
- Security testing of input handling

**Status**: Implemented - Input validation throughout codebase
**Last Review**: 2026-06-26

---

### DF-003: Insufficient Access Control

**Description**: Design lacks comprehensive access control mechanisms.

**Potential Issues**:
- All users have same permissions
- No role-based access control
- Access control at UI level (not API level)
- Shared accounts or credentials
- Missing authorization enforcement

**Mitigations**:
- Role-based access control (RBAC) enforced at API level
- Principle of least privilege (default deny)
- Per-resource authorization checks
- Audit logging of access control decisions
- Regular access review and cleanup

**Status**: Implemented - RBAC throughout system
**Last Review**: 2026-06-26

---

### DF-004: Inadequate Logging

**Description**: Insufficient logging for security monitoring and incident response.

**Potential Issues**:
- Not logging security-relevant events
- Logs not persistent or encrypted
- Insufficient log retention
- No audit trail for accountability
- Logs accessible to unauthorized users

**Mitigations**:
- Comprehensive audit logging (authentication, authorization, data access, changes)
- Immutable log storage (append-only)
- Log encryption for confidentiality and integrity
- Minimum 90-day retention (configurable)
- Restricted log access (authorized users only)
- Automated log monitoring and alerting

**Status**: Implemented - Comprehensive audit logging system
**Last Review**: 2026-06-26

---

## Threat Assessment Summary

### Threat Severity Distribution
| Severity | Count | Percentage |
|----------|-------|------------|
| Critical (9.0-10.0) | 4 | 22% |
| High (7.0-8.9) | 11 | 61% |
| Medium (4.0-6.9) | 2 | 11% |
| Low (0.1-3.9) | 0 | 0% |
| **Total** | **17** | **100%** |

### Mitigation Coverage
| Status | Count |
|--------|-------|
| Preventive Controls Implemented | 17/17 |
| Detective Controls Implemented | 17/17 |
| Corrective Controls Implemented | 17/17 |

### Design Flaw Coverage
| Design Flaw | Status |
|------------|--------|
| Cryptographic Weakness | Mitigated |
| Missing Input Validation | Mitigated |
| Insufficient Access Control | Mitigated |
| Inadequate Logging | Mitigated |

---

## Threat Model Maintenance

**Update Triggers**:
- Significant architectural changes
- New features affecting threat landscape
- Discovered vulnerabilities or incidents
- Annual threat model review
- External security assessments

**Next Threat Model Review**: June 26, 2027

---

**Document Version**: 1.0  
**Last Updated**: June 26, 2026  
**Reviewed By**: Security Maintainer  
**Approved By**: Project Lead
