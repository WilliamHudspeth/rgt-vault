package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/secfile"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// Seams for the provisioning backends: tests replace them (there is no TPM
// or DPAPI on a CI runner).
var (
	sealDPAPI       = providers.SealDPAPI
	sealMacOS       = providers.SealMacOSKeychain
	sealTPM         = providers.SealTPM
	keyringProvider = func() vault.MasterProvider { return providers.NewKeyringProvider("", "") }
	// stdoutIsTerminal reports whether w is a terminal (seal file --out -; enroll.go).
	stdoutIsTerminal = isTerminal
)

func newSealFileCmd(stdout io.Writer) *cobra.Command {
	var src masterSource
	var out string
	var force bool
	cmd := &cobra.Command{
		Use:   "file",
		Short: "Write the master secret to a key file for `--provider file`",
		Long: "Write the master secret as urlsafe-base64 of 32 bytes plus a newline (the keyring's text form) to\n" +
			"--out, created 0600 with O_EXCL (Windows: an owner+SYSTEM DACL). It is the migration path from the\n" +
			"keyring (--from-keyring) and the way to provision a key before `init --provider file\n" +
			"--master-key-file PATH`. --out - writes to standard output, only when it is not a terminal (to\n" +
			"pipe into `systemd-creds encrypt`). An existing file is replaced only with --force.\n\n" +
			"A key file is weaker than TPM or DPAPI at rest unless it is delivered as an encrypted systemd\n" +
			"credential: docs/guides/providers.md.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return errors.New("--out PATH is required (\"-\" for standard output)")
			}
			secret, err := src.secret(false)
			if err != nil {
				return err
			}
			defer providers.Wipe(secret)
			if len(secret) != providers.MasterSecretSize {
				return fmt.Errorf("the file provider holds exactly %d bytes; this source has %d "+
					"(a --master-file must hold exactly 32 raw bytes)", providers.MasterSecretSize, len(secret))
			}
			text := providers.EncodeKeyFile(secret)
			defer providers.Wipe(text)
			if out == "-" {
				if stdoutIsTerminal(stdout) {
					return errors.New("refusing to print the master key to a terminal: redirect it (--out - | systemd-creds encrypt ...) or use --out PATH")
				}
				_, err := stdout.Write(text)
				return err
			}
			path, err := server.ExpandHome(out)
			if err != nil {
				return err
			}
			if err := refuseOverwrite(path, force); err != nil {
				return err
			}
			if err := secfile.EnsureDir(filepath.Dir(path)); err != nil {
				return err
			}
			write := secfile.CreateSecret
			if force {
				write = secfile.ReplaceSecret
				// The key being replaced may be a live vault's: keep it as
				// <key>.prev (never over an existing .prev), and drop the
				// vault binding so the new key can serve a new vault.
				if old, err := secfile.OpenSecret(path, secfile.Options{MaxSize: providers.MaxKeyFileSize}); err == nil {
					err = secfile.CreateSecret(providers.PrevPath(path), old)
					providers.Wipe(old)
					if err != nil {
						return fmt.Errorf("keeping the replaced key as %s: %w (check and remove it first)", providers.PrevPath(path), err)
					}
					fmt.Fprintf(stdout, "The replaced key is kept in %s.\n", providers.PrevPath(path))
				} else if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("refusing to replace %s: %w", path, err)
				}
				if err := os.Remove(providers.VaultIDPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			if err := write(path, text); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Wrote the master key to %s (0600).\nUse it with: rgt-vault --provider file --master-key-file %s serve\n", path, path)
			return nil
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&out, "out", "", "key file to write, or - for standard output (not a terminal)")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing key file")
	return cmd
}

func newProviderCmd(stdin io.Reader, stdout io.Writer) *cobra.Command {
	prov := &cobra.Command{
		Use:   "provider",
		Short: "Provision a master-secret provider for `--provider platform` or `--provider file`",
	}
	seal := &cobra.Command{
		Use:   "seal",
		Short: "Seal the master secret into the Windows DPAPI, macOS Keychain or Linux TPM backend, or a key file",
	}
	seal.AddCommand(newSealDPAPICmd(stdout), newSealMacOSCmd(stdout), newSealTPMCmd(stdout), newSealFileCmd(stdout))
	prov.AddCommand(seal)
	return prov
}

// masterSource are the flags that say where the secret to seal comes from.
// The secret is never printed.
type masterSource struct {
	generate    bool
	masterFile  string
	fromKeyring bool
}

func (m *masterSource) register(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&m.generate, "generate", false, "seal a fresh random 32-byte master secret (for a NEW vault)")
	cmd.Flags().StringVar(&m.masterFile, "master-file", "", "seal the exact bytes of this file (use it to move an existing vault's secret)")
	cmd.Flags().BoolVar(&m.fromKeyring, "from-keyring", false, "seal the master secret currently in the OS keyring (rgt_vault/master_key)")
}

// secret returns the bytes to seal. text asks for printable ASCII (the macOS
// Keychain stores text).
func (m *masterSource) secret(text bool) ([]byte, error) {
	n := 0
	for _, set := range []bool{m.generate, m.masterFile != "", m.fromKeyring} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, errors.New("choose exactly one of --generate, --master-file, --from-keyring")
	}
	switch {
	case m.generate:
		b := make([]byte, providers.MasterSecretSize)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generating master secret: %w", err)
		}
		if text {
			enc := []byte(base64.StdEncoding.EncodeToString(b))
			providers.Wipe(b)
			return enc, nil
		}
		return b, nil
	case m.masterFile != "":
		p, err := server.ExpandHome(m.masterFile)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading master file: %w", err)
		}
		if text {
			b = bytes.TrimRight(b, "\r\n")
		}
		if len(b) == 0 {
			return nil, errors.New("master file is empty")
		}
		return b, nil
	default:
		b, err := keyringProvider().GetMasterSecret()
		if err != nil {
			return nil, fmt.Errorf("reading the keyring master secret: %w", err)
		}
		return b, nil
	}
}

// refuseOverwrite stops a seal from replacing an existing sealed blob: a
// different secret there would orphan the vault that uses it.
func refuseOverwrite(path string, force bool) error {
	if force {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists: sealing a different secret over it would lock you out of its vault; pass --force to replace it", path)
	}
	return nil
}

func newSealDPAPICmd(stdout io.Writer) *cobra.Command {
	var src masterSource
	var out, entropyFile string
	var force bool
	cmd := &cobra.Command{
		Use:   "dpapi",
		Short: "Seal with Windows DPAPI (machine scope) into a blob file",
		Long: "Protect the master secret with CryptProtectData and write base64 of the blob to --out (0600).\n" +
			"Run on the Windows machine that serves the vault; read it back with `--provider platform` and\n" +
			"VAULT_DPAPI_BLOB=<out>.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, err := src.secret(false)
			if err != nil {
				return err
			}
			defer providers.Wipe(secret)
			path, err := server.ExpandHome(firstNonEmpty(out, os.Getenv(providers.EnvDPAPIBlob), providers.DefaultDPAPIBlobPath))
			if err != nil {
				return err
			}
			if err := refuseOverwrite(path, force); err != nil {
				return err
			}
			var entropy []byte
			if entropyFile != "" {
				if entropy, err = os.ReadFile(entropyFile); err != nil {
					return fmt.Errorf("reading entropy file: %w", err)
				}
			}
			if err := sealDPAPI(secret, path, entropy); err != nil {
				return fmt.Errorf("sealing with DPAPI: %w", err)
			}
			fmt.Fprintf(stdout, "Sealed the master secret with DPAPI into %s\nUse it with: VAULT_DPAPI_BLOB=%s rgt-vault serve --provider platform\n", path, path)
			return nil
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&out, "out", "", "blob file (env "+providers.EnvDPAPIBlob+", default "+providers.DefaultDPAPIBlobPath+")")
	cmd.Flags().StringVar(&entropyFile, "entropy-file", "", "optional DPAPI entropy (the same bytes are needed to unseal)")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing blob")
	return cmd
}

func newSealMacOSCmd(stdout io.Writer) *cobra.Command {
	var src masterSource
	var service, account string
	var update bool
	cmd := &cobra.Command{
		Use:   "macos",
		Short: "Seal into a macOS login-keychain item",
		Long: "Store the master secret as a generic-password item with `security`. The item holds TEXT:\n" +
			"--generate stores base64 of 32 random bytes; --master-file must hold printable ASCII.\n" +
			"An existing item is only replaced with --update.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, err := src.secret(true)
			if err != nil {
				return err
			}
			defer providers.Wipe(secret)
			service = firstNonEmpty(service, os.Getenv(providers.EnvKeychainService), providers.DefaultMacOSService)
			account = firstNonEmpty(account, os.Getenv(providers.EnvKeychainAccount), providers.DefaultMacOSAccount)
			if err := sealMacOS(secret, service, account, update); err != nil {
				return fmt.Errorf("sealing into the macOS keychain: %w", err)
			}
			fmt.Fprintf(stdout, "Stored the master secret in the macOS keychain (service %q, account %q).\nUse it with: rgt-vault serve --provider platform\n", service, account)
			return nil
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&service, "service", "", "keychain service (env "+providers.EnvKeychainService+", default "+providers.DefaultMacOSService+")")
	cmd.Flags().StringVar(&account, "account", "", "keychain account (env "+providers.EnvKeychainAccount+", default "+providers.DefaultMacOSAccount+")")
	cmd.Flags().BoolVar(&update, "update", false, "replace an existing item")
	return cmd
}

func newSealTPMCmd(stdout io.Writer) *cobra.Command {
	var src masterSource
	var outDir, bank string
	var pcrs []int
	var force bool
	cmd := &cobra.Command{
		Use:   "tpm",
		Short: "Seal to the Linux TPM 2.0 with tpm2-tools and a PCR policy",
		Long: "Seal the master secret to a TPM PCR policy and write master_secret.priv, master_secret.pub and\n" +
			"master_secret.pcrs into --out-dir (needs tpm2-tools and access to the TPM). Read it back with\n" +
			"`--provider platform` and VAULT_TPM_PRIV / VAULT_TPM_PUB.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, err := src.secret(false)
			if err != nil {
				return err
			}
			defer providers.Wipe(secret)
			dir := outDir
			if dir == "" {
				if priv := os.Getenv(providers.EnvTPMPrivate); priv != "" {
					dir = filepath.Dir(priv)
				} else {
					dir = filepath.Dir(providers.DefaultTPMPrivatePath)
				}
			}
			dir, err = server.ExpandHome(dir)
			if err != nil {
				return err
			}
			if err := refuseOverwrite(filepath.Join(dir, "master_secret.priv"), force); err != nil {
				return err
			}
			priv, pub, err := sealTPM(secret, dir, pcrs, bank)
			if err != nil {
				return fmt.Errorf("sealing to the TPM: %w", err)
			}
			fmt.Fprintf(stdout, "Sealed the master secret to the TPM.\n  %s=%s\n  %s=%s\nUse them with: rgt-vault serve --provider platform\n",
				providers.EnvTPMPrivate, priv, providers.EnvTPMPublic, pub)
			return nil
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory for the sealed blobs (default: the directory of "+providers.EnvTPMPrivate+", else "+filepath.Dir(providers.DefaultTPMPrivatePath)+")")
	cmd.Flags().IntSliceVar(&pcrs, "pcr", nil, "PCR indexes of the policy (default 0,7)")
	cmd.Flags().StringVar(&bank, "pcr-bank", "", "PCR bank (default "+providers.DefaultPCRBank+")")
	cmd.Flags().BoolVar(&force, "force", false, "replace existing blobs")
	return cmd
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
