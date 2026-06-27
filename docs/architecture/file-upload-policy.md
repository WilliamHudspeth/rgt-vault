# File Upload Security Policy

## Current State

rgt-vault **does not expose a file upload endpoint**. The API surface is:

- `POST /v1/secrets` — stores a secret *value* (a string, max 1 MB), never a file.
- `POST /v1/secrets/{ns}/{name}/use` — executes an action against a leased secret; params are JSON scalars.
- All other endpoints are read, audit, or administrative operations.

Tickets RGT-386 to RGT-391, RGT-425, and RGT-439 to RGT-441 are addressed by
this policy document because the vault intentionally has no file upload surface.
The controls below define what MUST be implemented if a file upload endpoint is
ever added.

---

## Required Controls if a File Upload Endpoint is Added

### RGT-386: Extension Allowlisting and Size Limits

- Maintain a strict allowlist of permitted extensions (e.g. `[".json", ".yaml", ".pem"]`).
  The list must be defined at the server, not inferred from the client-supplied filename.
- Maximum file size: 10 MB (reject before writing to disk).
- ZIP/archive files must be inspected before extraction:
  - Reject if any entry's target path contains `..`, `/`, or `\`.
  - Reject if the compression ratio exceeds 100:1 (zip bomb guard).
  - Reject if the uncompressed size would exceed the size limit.

### RGT-387: Server-Side Naming

- Client-supplied filenames MUST NOT be used as storage paths.
- Every stored file is assigned a random UUID-based name generated server-side
  (`secrets.token_hex(16)`).
- The client-to-server mapping is stored in the database; the client receives
  an opaque reference ID, never a filesystem path.

### RGT-388: Malware Scanning

- Uploaded files must be scanned with a ClamAV or equivalent AV engine before
  storage. The scan runs in a restricted sandbox with no network access.
- If no AV engine is configured, the endpoint must refuse upload with 503.

### RGT-389: Image Validation

- Image files must be rewritten through Pillow's `Image.open` / `Image.save`
  pipeline to strip metadata and EXIF payloads.
- The detected content type (via `imghdr` or `python-magic`) must match the
  allowlisted extension. A file with a `.jpg` extension that starts with a PHP
  header is rejected.

### RGT-390: Executable Extension Blocklist

Even under the allowlist model, explicitly reject any file whose extension
(including secondary extensions, e.g. `.php.jpg`) contains:

```
asp, aspx, config, ashx, asmx, aspq, axd, cshtm, cshtml, rem, soap,
vbhtm, vbhtml, asa, asax, ascx, browser, master, sitemap, skin, config,
php, php3, php4, php5, php7, phtml, xml (.htaccess, crossdomain.xml,
clientaccesspolicy.xml, .htpasswd), cgi, pl, py, rb, sh, cmd, bat,
ps1, jsp, jspx, jspf, jspa, jsw, jsv, jtml, do, action, html, htm, js
```

### RGT-391: Email Address Validation

Implemented in `python/email_verification.py` via `is_valid_email_syntax()`:
- Local part ≤ 63 characters (validated via the regex).
- Total length ≤ 254 characters.
- Allowlist regex: `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
- Mail server exceptions are caught and do not disclose internal paths.

**Status: Implemented.**

### RGT-425: WSTG File Upload Defense

Controls required:
1. Extension verified server-side (see RGT-386 allowlist).
2. Magic header verification via `python-magic` for MIME type cross-check.
3. No direct URL execution of uploaded files — the upload directory is not
   served as a web root; files are served only via authenticated download
   endpoints that set `Content-Disposition: attachment`.
4. ZIP path traversal prevention (see RGT-386).
5. Allowed file type list is documented and change-controlled.

### RGT-439: No Execute Permissions on Upload Directory

- The upload storage directory is created with mode `0o750` (owner rwx,
  group r-x, world ---).
- No file within the upload directory is stored with execute bits:
  `os.chmod(dest_path, 0o640)` is applied after every write.
- The web server (uvicorn) does not have a static-file handler pointing at
  the upload directory.

### RGT-440: NTFS / OS-Reserved Filename Sanitization

Before storing under a server-side name, validate the original client
filename against:
- Colons (`:`) — NTFS alternate data streams.
- Trailing spaces or dots — Windows/FAT artefacts.
- OS-reserved names: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`.

If any of these are detected, the upload is rejected with 400 (Bad Request).
The random server-side name is never derived from the client name, so this
check is defence-in-depth, not the primary protection.

### RGT-441: Filename Collision Resolution

- Server-side names are generated via `secrets.token_hex(16)` (128 bits of
  randomness); collision probability is negligible.
- On the unlikely event of a collision in the database index, the upload is
  retried with a new random name up to 3 times before returning 500.
- Error responses do not disclose the filesystem path or the conflicting name.

---

## Enforcement

If a file upload endpoint is proposed:
1. Open a new ticket linking to this document.
2. All controls above must be implemented and tested before the endpoint
   can be merged.
3. A security review (RGT-level) is required before enabling in production.
