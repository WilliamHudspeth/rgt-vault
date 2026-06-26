# Handoff Report: Build Hardening & Dependency Governance (Milestone 4)

## 1. Observation
I observed the following files and build settings in the `rgt-vault` codebase:
* **Swagger/ReDoc UI serving**:
  In `python/server/app.py` (lines 188-198), FastAPI is instantiated using default routes:
  ```python
  is_prod = os.getenv("APP_ENV") == "production"

  app = FastAPI(
      title="rgt-vault",
      version="0.2.0" if not is_prod else "",
      description="Local HTTP surface for the rgt-vault secrets manager.",
      debug=os.getenv("RGT_VAULT_DEBUG", "0") == "1",
      docs_url=None if is_prod else "/docs",
      redoc_url=None if is_prod else "/redoc",
      openapi_url=None if is_prod else "/openapi.json",
  )
  ```
  This serves dynamic Swagger/ReDoc assets using default FastAPI JS/CSS CDN endpoints without integrity check attributes.
* **Go dependency and build configuration**:
  In `go/go.mod` (lines 1-5), the project uses Go 1.25.0. In `go/.goreleaser.yaml` (lines 9-26), the build job builds Go executables with CGO disabled and debug information stripped:
  ```yaml
  builds:
    - id: rgt-vault
      main: ./cmd/rgt-vault
      binary: rgt-vault
      env:
        - CGO_ENABLED=0
      # ...
      ldflags:
        - -s -w
  ```
  No `-buildmode=pie` flag is configured.
* **Python build layout**:
  In `pyproject.toml` (lines 1-3), the package is built using setuptools:
  ```toml
  [build-system]
  requires = ["setuptools>=61.0"]
  build-backend = "setuptools.build_meta"
  ```
  A search for custom C source files (`.c`, `.cpp`, `.h`, `.pyx`) yielded zero results, confirming that the Python code is pure Python with no native binary extensions.

## 2. Logic Chain
1. **RGT-451 (SRI for CDN Assets)**:
   * *Observation*: FastAPI serves documentation at `/docs` using floating CDN URLs without SRI integrity verification.
   * *Reasoning*: Because these assets are loaded by the browser from a external CDN, any compromise of the CDN host could lead to remote script tampering.
   * *Solution*: The application must disable default documentation routes and manually register custom ones. These custom endpoints must generate the HTML page but replace the stylesheet and script tags with versions containing static pinned URLs (e.g. `swagger-ui-dist@5.17.14`) and W3C `integrity` and `crossorigin` attributes.
2. **RGT-450 (Dependency Freshness & SBOM)**:
   * *Observation*: The project uses Python dependencies (`pyproject.toml`, `requirements.txt`) and Go modules (`go/go.mod`).
   * *Reasoning*: Because the project comprises two separate language ecosystems, we require a tool capable of auditing and generating metadata for both.
   * *Solution*: Incorporating the Anchore `syft` scan tool inside the CI workflow automates the generation of a combined CycloneDX JSON SBOM. Weekly Dependabot runs will check both ecosystems for updates, and enabling blocking scans for `pip-audit` and `govulncheck` guarantees that no known vulnerabilities block production.
3. **RGT-449 (Compiler Hardening)**:
   * *Observation*: Go binaries are compiled using GoReleaser without ASLR-enabling flags, and CGO is disabled (`CGO_ENABLED=0`). No C extensions exist in Python.
   * *Reasoning*: Compiling Go binaries without PIE mode prevents the OS from applying Address Space Layout Randomization, leaving them more susceptible to memory execution exploits. Since CGO is disabled, memory safety issues at the C-level are already prevented.
   * *Solution*: Adding `-buildmode=pie` under `flags` in `go/.goreleaser.yaml` configures the Go compiler to generate Position Independent Executables. No native compiler hardening is needed for the pure Python codebase, but setting `CFLAGS` and `LDFLAGS` during the deployment pip install stage secures compiled Python dependency wheels if built from source.

## 3. Caveats
* **CDN Offline Failures**: If an operator opens the `/docs` page in an environment without internet access, the CDN assets will fail to load even if SRI is valid. Local hosting of Swagger UI assets remains the ultimate best practice for strictly isolated environments.
* **OS Compatibility**: While `-buildmode=pie` is widely supported, compiling for certain ancient or exotic architectures might fail. However, for all primary target targets (Linux, macOS, and Windows on amd64/arm64), Go supports PIE mode.

## 4. Conclusion
We have formulated a robust and complete strategy to harden build processes and manage dependencies:
1. Override default FastAPI OpenAPI endpoints to inject static SRI hashes for CDN-loaded documentation assets.
2. Integrate `syft` in CI to produce standard SBOMs, configure weekly Dependabot updates, and add `govulncheck` to the CI pipeline.
3. Apply `-buildmode=pie` in `go/.goreleaser.yaml` to enforce PIE/ASLR protections while maintaining `CGO_ENABLED=0`.

## 5. Verification Method
* **RGT-451**: Query `/docs` using the FastAPI TestClient (or pytest) and verify that:
  - Pinned version `5.17.14` is used.
  - The script tags contain `integrity="sha384-..."` and `crossorigin="anonymous"`.
* **RGT-450**: Verify in the CI pipeline that the output file `build/sbom.cyclonedx.json` is generated, has valid JSON syntax, and contains dependencies from both Go (`go/go.mod`) and Python (`pyproject.toml`).
* **RGT-449**: Build the Go binary using `go build -buildmode=pie -o build/rgt-vault ./cmd/rgt-vault` and verify PIE support programmatically:
  - On Linux, run `file build/rgt-vault` and assert it outputs "pie executable" or "shared object".
  - Alternatively, write an ELF header parser test that confirms that byte offsets 16-17 of the compiled binary match ELF type `ET_DYN` (shared object/PIE value `0x03`).
