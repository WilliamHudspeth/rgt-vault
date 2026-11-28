// Package logging provides a hardened, stdlib-only structured JSON logger
// built on log/slog for the Go line of rgt-vault (ASVS V7 / RGT-247, RGT-409,
// RGT-415, RGT-428).
//
// Properties enforced on every record:
//   - Single-line JSON output with UTC RFC3339Nano timestamps and stable keys
//     ("time", "level", "msg", plus typed domain field constants).
//   - Key- and value-based credential scrubbing across top-level attributes,
//     slog groups, WithAttrs/WithGroup chains, maps, http.Header, slices,
//     structs, raw byte slices, and error strings (bearer tokens, secret
//     values, master/DEK keys, capability tokens, TOTP codes and URIs,
//     Authorization/Cookie headers, and URL userinfo passwords).
//   - Control-character encoding across messages, keys, and string values
//     (\r, \n, \t, ESC/ANSI sequences, C0/DEL, Unicode C1, line/paragraph
//     separators, and BiDi override characters) so untrusted inputs cannot
//     forge log lines or hijack operator terminals.
//
// Other packages (server, CLI, MCP) adopt this package in batches G9/G10.
package logging
