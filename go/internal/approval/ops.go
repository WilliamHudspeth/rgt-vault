package approval

import (
	"fmt"
	"sort"
	"strings"
)

// GatedOp is a mutating operation an operator can require approval for
// (--require-approval-for). Reads are gated by --require-approval.
type GatedOp string

// The operations that can be gated.
const (
	OpSet    GatedOp = "set"
	OpRotate GatedOp = "rotate"
	OpRevoke GatedOp = "revoke"
)

// AllGatedOps lists every gate-able operation, sorted.
var AllGatedOps = []GatedOp{OpRevoke, OpRotate, OpSet}

// ParseGatedOps parses a comma-separated list such as "set,rotate,revoke"
// ("all" selects every operation, "" none). Names are case-insensitive;
// unknown names, including "read", are an error so a typo cannot silently
// leave an operation ungated. The result is sorted and has no duplicates.
func ParseGatedOps(list string) ([]GatedOp, error) {
	seen := map[GatedOp]bool{}
	for _, part := range strings.Split(list, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		switch name {
		case "":
			continue
		case "all":
			for _, o := range AllGatedOps {
				seen[o] = true
			}
		case string(OpSet), string(OpRotate), string(OpRevoke):
			seen[GatedOp(name)] = true
		case "read":
			return nil, fmt.Errorf("approval for reads is --require-approval, not an --require-approval-for value")
		default:
			return nil, fmt.Errorf("unknown operation %q in --require-approval-for (use set, rotate, revoke or all)", part)
		}
	}
	out := make([]GatedOp, 0, len(seen))
	for o := range seen {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// HasTOTP reports whether the broker has a TOTP verifier.
func (b *Broker) HasTOTP() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.totp != nil
}
