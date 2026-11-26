//go:build windows

package providers

import (
	"fmt"
	"unsafe" // This is the ONLY file in go/ that imports unsafe (allowlisted, RGT-374/375).

	"golang.org/x/sys/windows"
)

// The Win32 DATA_BLOB wrappers below need unsafe in exactly three places:
// taking the address of a Go slice's first byte, viewing the OS-allocated
// output buffer as a slice, and releasing it with LocalFree. Nothing here
// retains a pointer after the call returns.

// toBlob views b as a DATA_BLOB. The caller must keep b alive across the call.
func toBlob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies an OS-allocated output blob into Go memory, wipes it and
// frees it.
func takeBlob(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return nil
	}
	view := unsafe.Slice(out.Data, out.Size)
	defer func() { // wipe and free even if the copy below panics
		clear(view)
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	}()
	res := make([]byte, len(view))
	copy(res, view)
	return res
}

// maxBlob keeps len() within the DATA_BLOB uint32 size field.
const maxBlob = 1 << 30

func platformDPAPIUnprotect(blob, entropy []byte) ([]byte, error) {
	if len(blob) > maxBlob || len(entropy) > maxBlob {
		return nil, fmt.Errorf("DPAPI input too large")
	}
	in := toBlob(blob)
	var ent *windows.DataBlob
	if len(entropy) > 0 {
		e := toBlob(entropy)
		ent = &e
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, ent, 0, nil, dpapiLocalMachine, &out); err != nil {
		return nil, fmt.Errorf("DPAPI decryption failed: %w", err)
	}
	return takeBlob(&out), nil
}

func platformDPAPIProtect(secret, entropy []byte) ([]byte, error) {
	if len(secret) > maxBlob || len(entropy) > maxBlob {
		return nil, fmt.Errorf("DPAPI input too large")
	}
	in := toBlob(secret)
	var ent *windows.DataBlob
	if len(entropy) > 0 {
		e := toBlob(entropy)
		ent = &e
	}
	desc, err := windows.UTF16PtrFromString("Vault Master Secret")
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, desc, ent, 0, nil, dpapiLocalMachine, &out); err != nil {
		return nil, fmt.Errorf("DPAPI encryption failed: %w", err)
	}
	return takeBlob(&out), nil
}
