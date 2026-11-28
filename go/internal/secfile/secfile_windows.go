//go:build windows

package secfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// The ACL is inspected through its SDDL text (ConvertSecurityDescriptorTo
// StringSecurityDescriptor), so this file needs no package unsafe (RGT-374:
// dpapi_windows.go is the only file allowed to import it).

// securityAttributesSize is sizeof(SECURITY_ATTRIBUTES) {DWORD; LPVOID;
// BOOL}: 24 bytes on 64-bit Windows, 12 on 32-bit. Computed without package
// unsafe or reflect (both are allowlisted imports, RGT-374/379).
const securityAttributesSize = 12 * (strconv.IntSize / 32)

// currentUserSID is a seam for tests.
var currentUserSID = func() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

func openChecked(path string, opts Options) (*os.File, int64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, err
	}
	name, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return nil, 0, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, 0, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
		}
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), abs)
	size, err := checkHandle(h, abs, opts)
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, size, nil
}

func checkHandle(h windows.Handle, path string, opts Options) (int64, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := checkAttributes(path, info.FileAttributes, info.NumberOfLinks); err != nil {
		return 0, err
	}
	size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		err = insecure("%s: cannot read its ACL (%v)", path, err)
	} else {
		err = checkSecurity(path, sd)
	}
	if err != nil {
		if !opts.InsecureACL {
			return 0, err
		}
		opts.warn("WARNING: " + err.Error() + " (accepted because RGT_VAULT_INSECURE_KEY_ACL=1; diagnosis only)")
	}
	return size, nil
}

func checkAttributes(path string, attrs, links uint32) error {
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return insecure("%s is a reparse point (symlink or junction): point to the real file", path)
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return insecure("%s is not a regular file (directory)", path)
	case links != 1:
		return insecure("%s has %d hard links; a secret file must have exactly one (copy it to a new file)", path, links)
	}
	return nil
}

// trustedSIDs are the SIDs that may own the file or hold an allow ACE.
func trustedSIDs() ([]*windows.SID, error) {
	me, err := currentUserSID()
	if err != nil {
		return nil, fmt.Errorf("current user SID: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{me, system, admins}, nil
}

func isTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

const aclFix = "restrict it to you and SYSTEM: icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%:F\" /grant:r SYSTEM:F"

// checkSecurity applies the owner and DACL rules to sd.
func checkSecurity(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	trusted, err := trustedSIDs()
	if err != nil {
		return insecure("%s: %v", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return insecure("%s: cannot read its owner", path)
	}
	if !isTrusted(owner, trusted) {
		return insecure("%s is owned by %s, not by you, SYSTEM or Administrators: take ownership (takeown /f \"%s\")",
			path, owner.String(), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return insecure("%s has no readable DACL ("+aclFix+")", path, path)
	}
	if dacl == nil {
		return insecure("%s has a NULL DACL (everyone has full access): "+aclFix, path, path)
	}
	aces, err := daclACEs(sd.String())
	if err != nil {
		return insecure("%s: cannot parse its DACL (%v)", path, err)
	}
	for _, ace := range aces {
		if err := checkACE(ace, trusted); err != nil {
			return insecure("%s: %v: "+aclFix, path, err, path)
		}
	}
	return nil
}

// daclACEs returns the ACE strings of the D: part of an SDDL string.
func daclACEs(sddl string) ([]string, error) {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return nil, errors.New("no DACL in the security descriptor")
	}
	s := sddl[i+2:]
	if strings.HasPrefix(s, "NO_ACCESS_CONTROL") {
		return nil, errors.New("NULL DACL")
	}
	var aces []string
	depth, start := 0, -1
	for j, r := range s {
		switch r {
		case '(':
			if depth == 0 {
				start = j + 1
			}
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("unbalanced parentheses")
			}
			if depth == 0 {
				aces = append(aces, s[start:j])
			}
		case ':':
			if depth == 0 { // the next section (S:) starts
				return aces, nil
			}
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced parentheses")
	}
	return aces, nil
}

// checkACE accepts deny ACEs, inherit-only ACEs (they do not apply to the
// file) and allow ACEs for a trusted SID; everything else is refused.
func checkACE(ace string, trusted []*windows.SID) error {
	f := strings.Split(ace, ";")
	if len(f) < 6 {
		return fmt.Errorf("unparseable ACE %q", ace)
	}
	switch f[0] {
	case "D", "OD":
		return nil
	case "A":
	default:
		return fmt.Errorf("unsupported ACE type %q", f[0])
	}
	if strings.Contains(f[1], "IO") {
		return nil
	}
	sid, err := windows.StringToSid(f[5])
	if err != nil {
		return fmt.Errorf("ACE for unknown SID %q", f[5])
	}
	if !isTrusted(sid, trusted) {
		return fmt.Errorf("an ACE grants access to %s (%s)", accountName(sid), f[5])
	}
	return nil
}

func accountName(sid *windows.SID) string {
	acct, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain != "" {
		return domain + `\` + acct
	}
	return acct
}

// checkDirChain on Windows: the directory must be a real directory, not a
// reparse point. (The DACL of a directory under the user profile is the
// profile's; the file's own DACL is what is checked on read.)
func checkDirChain(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("directory %s: %w", dir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || fi.Mode()&fs.ModeIrregular != 0 {
		return insecure("directory %s is a reparse point", dir)
	}
	if !fi.IsDir() {
		return insecure("%s is not a directory", dir)
	}
	return nil
}

// protectedSA returns security attributes with a protected DACL that grants
// full access to the current user and SYSTEM only (no inheritance).
func protectedSA() (*windows.SecurityAttributes, error) {
	me, err := currentUserSID()
	if err != nil {
		return nil, fmt.Errorf("current user SID: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + me.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return nil, fmt.Errorf("build DACL: %w", err)
	}
	return &windows.SecurityAttributes{Length: securityAttributesSize, SecurityDescriptor: sd}, nil
}

// createExclusive creates path with CREATE_NEW and a protected DACL set at
// creation time, then writes data.
func createExclusive(path string, data []byte) error {
	sa, err := protectedSA()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("create %s: %w", path, fs.ErrExist)
		}
		return fmt.Errorf("create %s: %w", path, err)
	}
	return writeAndSync(os.NewFile(uintptr(h), path), path, data)
}

// Lock takes an exclusive LockFileEx lock on path (created with a protected
// DACL if missing) and returns the release function. It blocks while
// another handle holds the lock. The lock file is never removed.
func Lock(path string) (func(), error) { return lockFile(path, false) }

// tryLockOnce takes the lock without blocking; errWouldBlock if it is held.
func tryLockOnce(path string) (func(), error) { return lockFile(path, true) }

func lockFile(path string, nonBlocking bool) (func(), error) {
	sa, err := protectedSA()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	ol := new(windows.Overlapped)
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonBlocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	if err := windows.LockFileEx(h, flags, 0, 1, 0, ol); err != nil {
		_ = windows.CloseHandle(h)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errWouldBlock
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		_ = windows.CloseHandle(h)
	}, nil
}
