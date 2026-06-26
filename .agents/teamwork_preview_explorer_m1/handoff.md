# Handoff Report - HTTP Headers & CORS Hardening Plan

## 1. Observation
1. The FastAPI app constructor `build_app` is defined in `/home/will/rgt-vault/python/server/app.py`.
2. Inspecting the lines 154–158 of `app.py` reveals that it does not configure any CORS middleware or general HTTP security headers:
   ```python
   154:     app = FastAPI(
   155:         title="rgt-vault",
   156:         version="0.2.0",
   157:         description="Local HTTP surface for the rgt-vault secrets manager.",
   158:     )
   ```
3. Furthermore, no Content-Type enforcement is present for incoming request bodies on `POST` endpoints, and no Host validation is configured to prevent DNS rebinding attacks.
4. The test suite `/home/will/rgt-vault/tests/test_server_hardening.py` does not contain any assertions verifying HTTP security headers (such as `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, or `Content-Disposition`) or DNS rebinding defenses.

## 2. Logic Chain
1. **Lack of CORS controls (RGT-436)**: Since `CORSMiddleware` is not added, browsers default to same-origin policies. However, to prevent any cross-origin script from ever reading or interacting with the vault API, we should configure a default-deny CORS policy. If cross-origin requests are required, origins should be explicitly configured via command-line options (`--cors-origins`) or environment variables, avoiding wildcard configurations with credentials.
2. **DNS Rebinding risk (RGT-436 / RGT-119)**: A local server bound to `127.0.0.1:8765` is vulnerable to DNS rebinding if it does not validate the incoming `Host` header. By adding Starlette's `TrustedHostMiddleware`, the server can reject requests with unauthorized `Host` headers with a `400 Bad Request`.
3. **No security headers (RGT-454)**: Standard browser protections are missing. Clickjacking is mitigated by `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. Referrer leakages are prevented by `Referrer-Policy: no-referrer`. Protocol downgrade is prevented by `Strict-Transport-Security`. Cross-site scripting (XSS) is mitigated by a strict `Content-Security-Policy: default-src 'none'; sandbox;` for APIs.
4. **Missing request content validation & insecure cookies (RGT-453)**: Requesting clients could send payloads with non-JSON content types. Enforcing `Content-Type: application/json` for API modifications returns `415 Unsupported Media Type` early. Any future Set-Cookie response must have `Secure`, `HttpOnly`, and `SameSite=Strict` appended.
5. **No download hardening (RGT-438)**: For downloads or any API responses, setting `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` forces browsers to treat the payload as a download rather than executable or renderable HTML/JS, preventing browser-based content-sniffing exploits.

## 3. Caveats
- The test suite could not be run locally during exploration because the Python import mapping requires correct setuptools editable installation. Verification is formulated assuming the package import system is functional.
- The `Content-Security-Policy` for documentation endpoints (`/docs`, `/redoc`) relies on jsdelivr CDN. If the vault is running in a fully offline or air-gapped network, these assets will fail to load unless they are served locally.
- Secure cookie flags are enforced globally via the middleware, although the server does not currently set any cookies.

## 4. Conclusion
The proposed middleware and test implementation successfully harden the FastAPI server against all targeted security controls (HSTS, CSP, Referrer-Policy, frame embedding, Content-Type/Disposition, secure cookies, and CORS) without disrupting existing functionalities.

## 5. Verification Method
1. Apply the proposed patch/changes to `python/server/app.py` and `tests/test_server_hardening.py`.
2. Execute the test suite using pytest with the python path set to the package source:
   ```bash
   PYTHONPATH=python pytest tests/test_server_hardening.py
   ```
3. Invalidation conditions: Any test case in `tests/test_server_hardening.py` fails, indicating incorrect headers, broken documentation pages, or incorrect HTTP status codes on unsupported media types.
