# Installing rgt-vault (Go)

Here are several ways to get the `rgt-vault` CLI.

## From a release tarball (Linux/macOS)

Download the latest release tarball and its checksums:

```bash
# Determine your OS and architecture
OS=$(uname -s)   # returns "Linux" or "Darwin" — matches artifact naming exactly
case $(uname -m) in
  x86_64)  ARCH=x86_64 ;;
  aarch64) ARCH=arm64 ;;
  arm64)   ARCH=arm64 ;;
esac

# Download tarball and checksums
curl -L -o rgt-vault.tar.gz "https://github.com/WilliamHudspeth/rgt-vault/releases/latest/download/rgt-vault-go_${OS}_${ARCH}.tar.gz"
curl -L -o checksums.txt "https://github.com/WilliamHudspeth/rgt-vault/releases/latest/download/checksums.txt"

# Verify the SHA-256 hash (on macOS use `shasum -a 256`)
sha256sum --check <(grep "rgt-vault-go_${OS}_${ARCH}.tar.gz" checksums.txt)

# Extract the binary
tar -xzf rgt-vault.tar.gz

# Move it to your PATH
sudo mv rgt-vault /usr/local/bin/

# Test
rgt-vault --version
```

Release artifact names follow the pattern `rgt-vault-go_<OS>_<Arch>.tar.gz`, e.g.:

- `rgt-vault-go_Linux_x86_64.tar.gz`
- `rgt-vault-go_Darwin_arm64.tar.gz`
- `rgt-vault-go_Windows_x86_64.zip`

The checksum file is always named `checksums.txt`.

## Homebrew (macOS/Linux)

Coming with the signed release you can install via Homebrew (a tap will be announced):

```bash
brew install rgt-vault
```

## From source

Requires Go 1.25+.

```bash
git clone https://github.com/WilliamHudspeth/rgt-vault.git
cd rgt-vault/go
go build -o rgt-vault ./cmd/rgt-vault
sudo mv rgt-vault /usr/local/bin/
rgt-vault --version
```

## 5-minute quickstart

1. Create the vault, the per-agent token store (`~/.config/rgt-vault/tokens.json`, hashes only) and an operator token (`~/.config/rgt-vault/operator.token`, mode 0600; later commands read it automatically). Give each agent its own token with `rgt-vault token mint --agent NAME` (see `docs/guides/agent-identity-migration.md`). The master secret goes into the OS keyring. Safe to repeat: nothing existing is overwritten:
   ```bash
   rgt-vault init
   ```

2. Write a policy. With no policy every request is denied, so for this quickstart allow everything (use real rules for anything else, see the policies guide):
   ```bash
   cat > policy.yaml <<'YAML'
   rules:
     - effect: allow
       agent: "*"
       namespace: "*"
       purpose: "*"
       action: "*"
   YAML
   ```

3. Start the vault server in the background (127.0.0.1:8765; data persists in `~/.secure-vault/` across restarts):
   ```bash
   rgt-vault serve --policy policy.yaml &
   ```

4. Check the server health:
   ```bash
   rgt-vault status
   ```

5. Store a secret under the `prod` namespace:
   ```bash
   echo "my-secret-value" | rgt-vault set api-key --namespace prod
   ```

6. List secrets in `prod`:
   ```bash
   rgt-vault list --namespace prod
   ```

7. Retrieve the secret:
   ```bash
   rgt-vault get api-key --namespace prod
   ```

8. Verify the audit log integrity:
   ```bash
   rgt-vault verify-audit
   ```

> **Remote hosts:** when connecting to a remote rgt-vault server, pass `--token <token>` or set `RGT_VAULT_TOKEN` in your environment. After `rgt-vault init` the operator token is read from `~/.config/rgt-vault/operator.token` automatically (`RGT_VAULT_TOKEN_FILE` selects another file).

## Verifying the download

Each release ships with a Software Bill of Materials (SBOM) file (`rgt-vault-go_*.sbom.json`). If you have [syft](https://github.com/anchore/syft) installed you can inspect it:

```bash
syft rgt-vault-go_*.sbom.json
```
