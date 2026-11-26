package providers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Defaults of python/providers/__init__.py and linux_tpm.py.
const (
	DefaultTPMPrivatePath = "/etc/vault/sealed/master_secret.priv"
	DefaultTPMPublicPath  = "/etc/vault/sealed/master_secret.pub"
	DefaultPCRBank        = "sha256"
)

// defaultPCRList is the policy used when no <priv>.pcrs file is readable.
var defaultPCRList = []int{0, 7}

// TPMProvider unseals the master secret from a TPM 2.0 using the tpm2-tools
// command line, with a PCR policy session. It is a port of
// python/providers/linux_tpm.py LinuxTPMProvider.
//
// Every tool is started with an argv through [Runner]; errors carry the tool
// name and exit status only, never its stdout/stderr (RGT-371).
type TPMProvider struct {
	PrivatePath string
	PublicPath  string
	PCRBank     string
	PCRList     []int
	run         Runner
}

// TPMOption customises a TPMProvider.
type TPMOption func(*TPMProvider)

// WithPCRBank selects the PCR bank (default "sha256").
func WithPCRBank(bank string) TPMOption { return func(p *TPMProvider) { p.PCRBank = bank } }

// WithRunner replaces the external-command runner (for tests).
func WithRunner(r Runner) TPMOption { return func(p *TPMProvider) { p.run = r } }

// NewTPMProvider returns a provider for the sealed blobs. Like Python it
// requires both files to exist, and it reads the PCR list from
// "<priv basename without extension>.pcrs" (one line of space-separated
// integers), falling back to [0 7] if that file is missing or malformed.
func NewTPMProvider(privatePath, publicPath string, opts ...TPMOption) (*TPMProvider, error) {
	p := &TPMProvider{
		PrivatePath: privatePath,
		PublicPath:  publicPath,
		PCRBank:     DefaultPCRBank,
		PCRList:     append([]int(nil), defaultPCRList...),
		run:         execRunner,
	}
	for _, o := range opts {
		o(p)
	}
	if err := validPCRBank(p.PCRBank); err != nil {
		return nil, err
	}
	if !isRegular(privatePath) {
		return nil, fmt.Errorf("sealed private blob not found: %s: %w", privatePath, fs.ErrNotExist)
	}
	if !isRegular(publicPath) {
		return nil, fmt.Errorf("sealed public blob not found: %s: %w", publicPath, fs.ErrNotExist)
	}
	if text, err := os.ReadFile(pcrsPath(privatePath)); err == nil {
		if list, ok := parsePCRList(string(text)); ok {
			p.PCRList = list
		}
	}
	return p, nil
}

func isRegular(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// pcrsPath is Path(priv).with_suffix(".pcrs"): the last extension is replaced.
func pcrsPath(privatePath string) string {
	base := filepath.Base(privatePath)
	ext := filepath.Ext(base)
	if ext == base { // a dotfile such as ".priv" has no suffix in pathlib
		ext = ""
	}
	return privatePath[:len(privatePath)-len(ext)] + ".pcrs"
}

func parsePCRList(text string) ([]int, bool) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil, false
	}
	list := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || n > 31 {
			return nil, false
		}
		list = append(list, n)
	}
	return list, true
}

func validPCRBank(bank string) error {
	if bank == "" {
		return errors.New("PCR bank must not be empty")
	}
	for _, c := range bank {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return fmt.Errorf("invalid PCR bank %q", bank)
		}
	}
	return nil
}

// pcrSpec renders "sha256:0+sha256:7".
func pcrSpec(bank string, pcrs []int) string {
	parts := make([]string, len(pcrs))
	for i, n := range pcrs {
		parts[i] = bank + ":" + strconv.Itoa(n)
	}
	return strings.Join(parts, "+")
}

// tpmRun runs one tpm2-tools command and converts failures into output-free
// errors.
func tpmRun(ctx context.Context, run Runner, args ...string) error {
	_, err := run(ctx, args[0], args[1:], nil)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return fmt.Errorf("%w: tpm2-tools not found. Please install: sudo apt install tpm2-tools", ErrTPM)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w: permission denied. Ensure you have access to the TPM device (/dev/tpmrm0) "+
			"or run with appropriate privileges (e.g., the tss group)", ErrTPM)
	}
	return fmt.Errorf("%w: %s failed (%s)", ErrTPM, args[0], describeRunError(err))
}

// GetMasterSecret performs, in order: tpm2_createprimary, tpm2_load,
// tpm2_startauthsession, tpm2_policypcr, tpm2_unseal.
func (p *TPMProvider) GetMasterSecret() ([]byte, error) {
	ctx := context.Background()
	dir := filepath.Dir(p.PrivatePath)

	// P0-1: the unseal target is created next to the sealed blobs with an
	// explicit 0600 mode and refused otherwise; it holds the plaintext secret.
	outFile, err := os.CreateTemp(dir, ".rgt-unseal-*")
	if err != nil {
		return nil, fmt.Errorf("%w: cannot create unseal scratch file: %w", ErrTPM, err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	if err := os.Chmod(outPath, 0o600); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("%w: could not set 0600 permissions on %s; refusing to unseal master secret "+
			"to a file with permissive mode", ErrTPM, outPath)
	}
	// Context files derive their names from the unique unseal file, so
	// concurrent unseals (even in one process) never collide.
	ctxPath := outPath + ".child.ctx"
	primaryCtx := outPath + ".primary.ctx"
	sessionPath := outPath + ".session.ctx"

	defer func() {
		// Flush first (the tools read the saved context files), then unlink.
		// Python unlinked first, which made its flush calls fail silently.
		for _, h := range []string{ctxPath, primaryCtx, sessionPath} {
			if _, err := os.Stat(h); err == nil {
				_ = tpmRun(ctx, p.run, "tpm2_flushcontext", "-c", h)
			}
		}
		for _, f := range []string{outPath, ctxPath, primaryCtx, sessionPath} {
			_ = os.Remove(f)
		}
	}()

	// Modern tpm2-tools needs an explicit primary; -T is deliberately not
	// passed so TCTI auto-discovery is used.
	steps := [][]string{
		{"tpm2_createprimary", "-C", "o", "-G", "rsa", "-c", primaryCtx},
		{"tpm2_load", "-C", primaryCtx, "-u", p.PublicPath, "-r", p.PrivatePath, "-c", ctxPath},
		// An explicit policy session: `-p pcr:...` is unreliable with several PCRs.
		{"tpm2_startauthsession", "--policy-session", "-S", sessionPath},
		{"tpm2_policypcr", "-S", sessionPath, "-l", pcrSpec(p.PCRBank, p.PCRList)},
		{"tpm2_unseal", "-c", ctxPath, "-o", outPath, "-p", "session:" + sessionPath},
	}
	for _, args := range steps {
		if err := tpmRun(ctx, p.run, args...); err != nil {
			return nil, err
		}
	}

	secret, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read unsealed secret: %w", ErrTPM, err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: unsealed empty secret – PCR policy may have rejected release", ErrTPM)
	}
	return secret, nil
}

// RotateMasterSecret seals a fresh 32-byte secret with the same PCR policy
// into a scratch directory and renames the blobs over the existing ones.
// As in Python the three renames are not one atomic step.
func (p *TPMProvider) RotateMasterSecret() ([]byte, error) {
	secret, err := newMasterSecret()
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(p.PrivatePath), ".rgt-rotate-")
	if err != nil {
		Wipe(secret)
		return nil, fmt.Errorf("%w: cannot create rotation scratch dir: %w", ErrTPM, err)
	}
	defer os.RemoveAll(tmpDir)

	newPriv, newPub, err := sealTPM(context.Background(), p.run, secret, tmpDir, p.PCRList, p.PCRBank)
	if err != nil {
		Wipe(secret)
		return nil, err
	}
	if err := os.Rename(newPriv, p.PrivatePath); err != nil {
		Wipe(secret)
		return nil, fmt.Errorf("%w: install rotated private blob: %w", ErrTPM, err)
	}
	if err := os.Rename(newPub, p.PublicPath); err != nil {
		Wipe(secret)
		return nil, fmt.Errorf("%w: install rotated public blob: %w", ErrTPM, err)
	}
	if _, err := os.Stat(pcrsPath(newPriv)); err == nil {
		if err := os.Rename(pcrsPath(newPriv), pcrsPath(p.PrivatePath)); err != nil {
			Wipe(secret)
			return nil, fmt.Errorf("%w: install rotated PCR list: %w", ErrTPM, err)
		}
	}
	return secret, nil
}

// SealTPM seals masterSecret to the PCR policy (default [0 7] in bank sha256
// when pcrList is empty / bank is ""), writing master_secret.priv,
// master_secret.pub and master_secret.pcrs into outputDir. It returns the blob
// paths. Python: linux_tpm.seal_master_secret.
func SealTPM(masterSecret []byte, outputDir string, pcrList []int, pcrBank string) (privatePath, publicPath string, err error) {
	return sealTPM(context.Background(), execRunner, masterSecret, outputDir, pcrList, pcrBank)
}

func sealTPM(ctx context.Context, run Runner, masterSecret []byte, outDir string, pcrList []int, bank string) (string, string, error) {
	if len(pcrList) == 0 {
		pcrList = defaultPCRList
	}
	if bank == "" {
		bank = DefaultPCRBank
	}
	if err := validPCRBank(bank); err != nil {
		return "", "", err
	}
	for _, n := range pcrList {
		if n < 0 || n > 31 {
			return "", "", fmt.Errorf("invalid PCR index %d", n)
		}
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", "", fmt.Errorf("%w: create output dir: %w", ErrTPM, err)
	}
	privatePath := filepath.Join(outDir, "master_secret.priv")
	publicPath := filepath.Join(outDir, "master_secret.pub")

	// P0-1 (seal side): the plaintext secret only ever touches a 0600 file.
	sf, err := os.CreateTemp(outDir, ".rgt-seal-*")
	if err != nil {
		return "", "", fmt.Errorf("%w: cannot create seal scratch file: %w", ErrTPM, err)
	}
	secretFile := sf.Name()
	primaryCtx := filepath.Join(outDir, "primary.ctx")
	policyDigest := filepath.Join(outDir, "policy.digest")
	defer func() {
		for _, f := range []string{secretFile, primaryCtx, policyDigest} {
			_ = os.Remove(f)
		}
		// Flush the transient primary from TPM memory; failures are ignored.
		_, _ = run(ctx, "tpm2_flushcontext", []string{"-t"}, nil)
	}()
	if err := os.Chmod(secretFile, 0o600); err != nil {
		_ = sf.Close()
		return "", "", fmt.Errorf("%w: could not set 0600 on seal scratch file", ErrTPM)
	}
	if _, err := sf.Write(masterSecret); err != nil {
		_ = sf.Close()
		return "", "", fmt.Errorf("%w: write seal scratch file: %w", ErrTPM, err)
	}
	if err := sf.Close(); err != nil {
		return "", "", fmt.Errorf("%w: write seal scratch file: %w", ErrTPM, err)
	}

	// tpm2_createpolicy wants '+'-separated PCR items.
	spec := pcrSpec(bank, pcrList)
	steps := [][]string{
		{"tpm2_createpolicy", "--policy-pcr", "-l", spec, "-L", policyDigest},
		{"tpm2_createprimary", "-C", "o", "-G", "rsa", "-c", primaryCtx},
		{"tpm2_create", "-C", primaryCtx, "-i", secretFile, "-u", publicPath, "-r", privatePath, "-L", policyDigest, "-g", "sha256"},
	}
	for _, args := range steps {
		if err := tpmRun(ctx, run, args...); err != nil {
			return "", "", err
		}
	}

	// Persist the PCR list so unseal rebuilds exactly the same policy.
	nums := make([]string, len(pcrList))
	for i, n := range pcrList {
		nums[i] = strconv.Itoa(n)
	}
	if err := os.WriteFile(pcrsPath(privatePath), []byte(strings.Join(nums, " ")+"\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("%w: write PCR list: %w", ErrTPM, err)
	}
	return privatePath, publicPath, nil
}
