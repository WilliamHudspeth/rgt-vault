package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/vault"
)

func newExportCmd(vf *servecmd.VaultFlags, stdout io.Writer) *cobra.Command {
	var outFile string
	var force bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Dump the vault (ciphertext only) in Python's export format",
		Long: "Write every secret row (still encrypted), the audit log and the honeytokens as\n" +
			"base64(JSON), byte-compatible with Python's export_vault (v1): either line can import it.\n" +
			"Secrets are bound to this vault's id and key, so an export only restores into the same vault.\n\n" +
			"To stdout by default; with --out the file is created 0600 and an existing file is not\n" +
			"overwritten without --force.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExport(cmd, vf, outFile, force, stdout)
		},
	}
	cmd.Flags().StringVar(&outFile, "out", "", "write the export to this file (0600) instead of stdout")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing --out file")
	return cmd
}

func runExport(cmd *cobra.Command, vf *servecmd.VaultFlags, outFile string, force bool, stdout io.Writer) error {
	ctx := cmd.Context()
	stack, _, err := openStackFor(ctx, vf, false, false)
	if err != nil {
		return err
	}
	defer stack.Close()
	data, err := stack.Vault.Export(ctx)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if len(data) > vault.MaxImportBytes {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: this export is %d bytes; import refuses payloads above %d bytes (10 MiB)\n", len(data), vault.MaxImportBytes)
	}
	if outFile == "" {
		_, err = fmt.Fprintln(stdout, string(data))
		return err
	}
	p, err := server.ExpandHome(outFile)
	if err != nil {
		return err
	}
	created, err := writeSecretFile(p, append(data, '\n'), force)
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("%s already exists: use --force to overwrite it", p)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Exported to %s\n", p)
	return nil
}

func newImportCmd(vf *servecmd.VaultFlags, stdin io.Reader, stdout io.Writer) *cobra.Command {
	var inFile string
	var yes bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Replace the vault's secrets, audit log and honeytokens from an export",
		Long: "Read an export (from Go or Python, v1) from --in or stdin and replace this vault's secrets,\n" +
			"audit log and honeytokens with it, in one transaction. An export of another vault (different\n" +
			"vault_id) is refused. This REPLACES existing data, so --yes is required.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runImport(cmd, vf, inFile, yes, stdin, stdout)
		},
	}
	cmd.Flags().StringVar(&inFile, "in", "", "read the export from this file (default stdin)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm that the vault's current contents are replaced")
	return cmd
}

func runImport(cmd *cobra.Command, vf *servecmd.VaultFlags, inFile string, yes bool, stdin io.Reader, stdout io.Writer) error {
	if !yes {
		return errors.New("import replaces the vault's secrets, audit log and honeytokens: pass --yes to confirm")
	}
	var payload []byte
	var err error
	if inFile != "" {
		p, perr := server.ExpandHome(inFile)
		if perr != nil {
			return perr
		}
		payload, err = readFileLimited(p)
	} else {
		payload, err = readLimited(stdin)
	}
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	stack, _, err := openStackFor(ctx, vf, false, false)
	if err != nil {
		return err
	}
	defer stack.Close()
	if err := stack.Vault.Import(ctx, bytes.TrimSpace(payload)); err != nil {
		return fmt.Errorf("import: %w", err)
	}
	fmt.Fprintln(stdout, "Import complete.")
	return nil
}

// readFileLimited is readLimited on a file.
func readFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading import payload: %w", err)
	}
	defer f.Close()
	return readLimited(f)
}

// readLimited reads at most vault.MaxImportBytes+1 bytes, so an oversized
// input is rejected without being buffered whole.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, vault.MaxImportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading import payload: %w", err)
	}
	if len(b) > vault.MaxImportBytes {
		return nil, fmt.Errorf("import payload exceeds the maximum allowed size of %d MiB", vault.MaxImportBytes>>20)
	}
	return b, nil
}
