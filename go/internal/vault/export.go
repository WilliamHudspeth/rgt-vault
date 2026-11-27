package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"unicode/utf8"

	"rgt-vault-server/internal/store"
)

// Export dumps every secret row (ciphertext only), the audit log and the
// honeytokens, stamped with the vault id, as base64(json.dumps(data,
// indent=2)) — byte-identical to Python's export_vault, so either line can
// import it. Restoring it elsewhere fails: secrets are bound to this
// vault_id and DEK.
func (v *Vault) Export(ctx context.Context) ([]byte, error) {
	if err := v.rlock(); err != nil {
		return nil, err
	}
	defer v.mu.RUnlock()
	data, err := v.store.ExportData(ctx)
	if err != nil {
		return nil, err
	}
	doc := pyObject{
		{"secrets", data.Secrets},
		{"audit_logs", data.AuditLogs},
		{"honeytokens", data.Honeytokens},
		{"vault_id", v.vaultID},
	}
	js := pyDumpsIndent(doc, 2)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(js)))
	base64.StdEncoding.Encode(out, []byte(js))
	return out, nil
}

// pyB64Decode is base64.b64decode(s) with validate=False: characters outside
// the standard alphabet are discarded before decoding.
func pyB64Decode(s []byte) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			clean = append(clean, c)
		}
	}
	// Python stops at the first complete padded quantum; anything after it
	// is ignored. Trim trailing data after the padding the same way.
	if i := bytes.IndexByte(clean, '='); i >= 0 {
		// Keep only the padding that completes the 4-character quantum.
		pad := (4 - i%4) % 4
		end := i
		for end < len(clean) && end < i+pad && clean[end] == '=' {
			end++
		}
		clean = clean[:end]
	}
	return base64.StdEncoding.DecodeString(string(clean))
}

// Import replaces the secrets, audit log and honeytokens with a payload from
// Export (or Python's export_vault), in one transaction (python
// import_vault). A payload stamped with another vault's id is refused.
// Like Python it is not hook- or policy-gated: it is an operator action.
func (v *Vault) Import(ctx context.Context, b64Data []byte) error {
	if len(b64Data) > MaxImportBytes {
		return validationErr("Import payload exceeds the maximum allowed size of 10MB.")
	}
	raw, err := pyB64Decode(b64Data)
	if err != nil {
		return validationErr("Invalid import payload format: %v", err)
	}
	if !utf8.Valid(raw) {
		return validationErr("Invalid import payload format: payload is not valid UTF-8")
	}
	data, err := store.DecodeImportJSON(raw)
	if err != nil {
		return validationErr("Invalid import payload format: %v", err)
	}
	obj, ok := data.(map[string]any)
	if !ok {
		return validationErr("Invalid import payload format: top level must be a JSON object")
	}
	if pid, present := obj["vault_id"]; present && pid != nil {
		if s, isStr := pid.(string); !isStr || s != v.vaultID {
			return validationErr("Import refused: payload belongs to vault '%s', but this is vault '%s'. "+
				"Restore into the original vault (same keychain.json/DEK) or re-encrypt before importing.",
				fmt.Sprint(pid), v.vaultID)
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.usable(); err != nil {
		return err
	}
	if err := v.store.ImportData(ctx, obj); err != nil {
		return err
	}
	return v.logAudit(ctx, "IMPORT", store.Name("VAULT"), "Vault imported from external data")
}
