# Asymmetric (Ed25519) capability tokens: format v3

Status: implemented in Go (`go/internal/captoken`, RGT-46). Design issue: RGT-35.
Not wired into the CLI yet (see "Out of scope").

## Why

A v2 capability token is signed with HMAC-SHA256 under one shared secret
(`--harness-key-file`). Anyone who can verify a v2 token can also mint one,
for any agent and any capability. The vault and the harness are therefore one
trust domain, and the secret has to be copied to every verifier.

ADR-0004 asks for Ed25519 tokens: the issuer (harness) keeps the private key
and every verifier holds only public keys. A compromised verifier cannot mint
tokens, and several issuers can each have their own key.

## Constraints

1. **Additive and versioned.** v2 stays exactly as it is: the envelope, the
   canonical payload bytes, `token_id`, and the error classes Python writes to
   the audit log. The existing v2 vectors (`vectors_test.go`, generated from
   `python/token.py`) must keep passing unchanged. Nothing on disk changes.
2. **No algorithm agility in the token.** The verifier's configuration decides
   which algorithm applies. A field in the token never does.
3. **The HMAC key can never be a public key, and the reverse.**
4. **Same claim set and the same post-verification checks as v2.** Audience,
   context bindings, replay guard and vault behaviour stay the same. The
   vault's `TokenVerifier` interface does not change.

## Wire format v3

```
token        = b64url(payload_json) "." b64url(signature)      ; no padding
payload_json = canonical JSON (the same encoder as v2) of
               {"agent_id", "capability", "capability_version",
                "context_bindings", "exp", "kid", "v": 3}
signature    = Ed25519(private_key, SigningContextV3 || payload_json)
SigningContextV3 = "rgt-vault/captoken/v3/ed25519\x00"
token_id     = hex(sha256(payload_json))[:16]                  ; as v2
```

- The payload is the v2 claim set plus `kid`, with `"v": 3`. It is rendered
  by the same canonical encoder, which reproduces Python's
  `json.dumps(sort_keys=True, separators=(",", ":"))` with `ensure_ascii`.
  `TestV3CanonicalMatchesV2Encoder` pins this: drop `kid`, set `v` back to 2,
  and the bytes equal the v2 payload.
- The envelope has the same two-part shape as v2, so the parsing is shared
  (strict base64url with no padding, CR/LF rejected).
- The signature covers a fixed domain-separation prefix. The Ed25519 key then
  signs nothing that another protocol could accept.
- Ed25519 is RFC 8032 pure Ed25519, Go `crypto/ed25519` from the standard
  library, with no new dependency. Go's verifier rejects non-canonical `S`, so
  a signature cannot be malleated into a second valid token.
- v3 is stricter than v2 where v2 inherited Python leniencies. A v3 payload
  with a duplicate JSON key at any depth is refused; v2 keeps "last key
  wins". A v3 `exp <= 0` is refused; in v2 it means "never expires".
  v3 tokens longer than 16 KiB are refused before decoding
  (`TestV3Strictness`, `TestV3BadSignatures`). v2 behaviour is unchanged
  and pinned.
- `TestV3Vector` pins a vector from a deterministic test seed. It was checked
  against Python `cryptography`'s `Ed25519PrivateKey` over the same
  `json.dumps` bytes (identical token).

### Why not JWS/JWT

A JWS header carries `alg`, which is exactly the field behind algorithm
confusion. The repo already has a canonical encoder that is byte-compatible
with Python, and a JOSE library would be a new dependency. v3 keeps the
project's own envelope and fixes the algorithm to the version.

## Key ids (`kid`) and rotation

- `kid` is 1-64 characters of `[A-Za-z0-9._-]`. The default is
  `KeyID(pub) = hex(sha256(public_key))[:16]`.
- The verifier holds a map `kid -> public key`. Before the signature is
  checked, `kid` is used only to choose one of the verifier's own trusted
  keys. `kid` is inside the signed payload, so relabelling it breaks the
  signature (`TestV3KeyIDMismatch`). An unknown `kid` is a signature failure
  (`TokenSignatureError`), the same answer as a wrong key. This holds even
  when the token is signed by a trusted key: the `kid` is never ignored or
  defaulted (`TestV3UntrustedKidSignedByTrustedKey`).
- Rotation:
  1. Add the new public key to the verifiers.
  2. Switch the issuer to the new private key.
  3. Remove the old public key once its last token can have expired. That is
     at most the issuer's maximum TTL; the default capability TTL is minutes.
  `TestV3Rotation` covers the overlap and the retirement.
- Revocation is by expiry plus the existing single-use `ReplayGuard`. A
  compromised issuer key is revoked by removing its `kid` from the verifiers.

## Verifier-only deployment

- `NewEd25519Verifier(keys)` holds public keys only. Its `Sign` returns
  `ErrNoSigningKey`, which is not a token failure.
- `LoadEd25519PublicKeyFile` refuses a file that holds a private key, so a
  verifier is never given one by mistake.
- The issuer uses `Ed25519Signer` (`NewEd25519Signer(priv, kid)`). A test or a
  self-verifying issuer can attach one with `WithSigner`. The signer's public
  key must already be trusted under its `kid`.

## Trusted public keys must be real keys

Go's `crypto/ed25519` verifies with the cofactorless equation and accepts
any 32-byte encoding that decodes, including non-canonical ones. With a
small-order public key, forgeries verify. With the identity key, `R =
identity, S = 0` is a valid signature for any message; the test suite shows
this on the Go in use. `NewEd25519Verifier`, and so every loader, therefore
refuses:

- the encodings of the 8 small-order points;
- the two `x = 0` encodings that have the sign bit set;
- every non-canonical encoding (`y >= p`).

The blocklist values were checked independently: each point's order was
computed with exact integer arithmetic. A key derived from a private key
never trips these checks (`TestRejectWeakPublicKeys`). Mixed-order keys, a
small-order component added to a real key, can only come from the key
holder. They give an issuer nothing beyond what its own private key already
allows, so they are not refused.

## Key files

| File | Accepted contents | Rules (not checked on Windows) |
|---|---|---|
| public key | PEM `PUBLIC KEY` (PKIX) **only** | owner is the process user or root; not writable by group or others (`& 0o022 == 0`) |
| private key | PEM `PRIVATE KEY` (PKCS #8), or exactly 32 raw seed bytes | owner is the process user or root; no group or other access at all (`0600` or stricter) |

Raw 32 bytes are accepted for private keys only. A raw 32-byte file could be
either a public key or a private seed. If a public-key file could be raw, a
seed could end up in a world-readable "public" file and still load, so the
public-key file must be PEM.

The mode and the owner are checked on the opened file descriptor, so there
is no stat/open race. Only regular files are accepted, and at most 16 KiB is read. Trailing
data after the PEM block is refused, as is any non-Ed25519 key. Errors name
the file and never include key bytes. The test suite generates keys at test
time. No key material is committed.

## Algorithm-confusion defence

| Attack | Defence | Test |
|---|---|---|
| v2 HMAC token sent to the Ed25519 verifier | `v` must be 3, so the token gets `TokenVersionError` before any crypto | `TestAlgorithmConfusion` (2) |
| v3 token sent to the HMAC verifier | the HMAC check fails (`TokenSignatureError`). A v3 payload that is correctly HMAC'd still fails the `v` check | (4), (5) |
| An attacker HMACs a v3 payload using the known public key (RS256-to-HS256 style) | the Ed25519 verifier never runs HMAC. A 32-byte "signature" is malformed, and a 64-byte one does not verify | (3) |
| An operator points `--harness-key-file` at a PEM public key, turning a public key into an HMAC secret | **speed bump only:** `NewHMACTokenVerifier` refuses any secret that contains a PEM header. The real defence is that each verifier type is bound to one algorithm and one version (rows above), and that public keys are never configured through the HMAC flag | (1) |
| `alg` / `kid` injection | there is no `alg`. An added claim breaks the signature, and `kid` only indexes trusted keys | `TestV3BadSignatures` ("added alg claim") |
| `TokenFormat` sniffing | a v3 token is never classified as v2, so `TwoFactorHook` refuses it (v1 parse fails closed) | (6) |

Timing: Ed25519 verification uses only public data. The `kid` lookup and the
early refusals depend only on the attacker's own input, so there is no secret
to leak through timing. The HMAC path still uses `hmac.Equal`.

The one new refusal on an existing path (an HMAC secret that contains
`-----BEGIN`) rejects only a misconfiguration. Every existing HMAC key and
token keeps working.

- **Go and Python now differ here.** Python's `HMACTokenVerifier` still
  accepts such a secret. Python is end-of-life, so this is not ported back.
- **Why the HMAC verifier does not refuse a raw 32-byte secret that is also
  a valid Ed25519 point:** that check would not be sound. About half of all
  random 32-byte strings decode as a curve point, so it would reject many
  legitimate random keys. It also would not stop someone pasting a raw
  public key.

## Error mapping (audit)

v3 failures use the existing error kinds, so the vault's audit reasons
(`token: TokenSignatureError`, `TokenMalformedError`, `TokenVersionError`,
`TokenExpiredError`, `TokenReplayError`) and the HTTP answers do not change.
`TestEd25519ThroughVault` checks this end to end.

## Out of scope / follow-ups

- **CLI/server wiring.** A new flag (for example `--harness-pubkey-file`, one
  or more) on `serve`, and an issuer-side `mint` command. They would touch
  `go/internal/server/stack.go` and `servecmd`, which other open work is
  changing. Tracked as RGT-519.
- `TwoFactorHook` accepts only v1/v2 tokens. A v3 token there is refused
  (fail closed).
- Python is end-of-life and gets no v3 support. A Python HMAC verifier
  rejects a v3 token as `TokenSignatureError`, because the signature is not
  an HMAC under its key.
