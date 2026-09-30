package secgate

import (
	"context"
	"strings"
)

// Allowlist is the set of permitted binary base names (lowercased).
type Allowlist struct{ bins map[string]bool }

// NewAllowlist builds an allowlist from binary names or paths (matched by base
// name, case-insensitively).
func NewAllowlist(bins ...string) *Allowlist {
	m := map[string]bool{}
	for _, b := range bins {
		if n := strings.ToLower(baseName(strings.TrimSpace(b))); n != "" {
			m[n] = true
		}
	}
	return &Allowlist{bins: m}
}

// Permits reports whether binary is an allowlisted bare command name. A binary
// that contains a path separator is denied (a base-name match would let a
// planted /tmp/attacker/nmap run under the nmap entry). An empty allowlist
// permits nothing.
func (a *Allowlist) Permits(binary string) bool {
	b := strings.TrimSpace(binary)
	if b == "" || strings.ContainsAny(b, `/\`) {
		return false
	}
	return a.bins[strings.ToLower(b)]
}

// Confirmer asks the human to approve one command (used in /safe). A nil
// Confirmer denies.
type Confirmer interface {
	Confirm(ctx context.Context, c Command) bool
}

// SessionApprovals remembers approved command signatures for this session.
type SessionApprovals struct{ approved map[string]bool }

// NewSessionApprovals returns an empty approvals set.
func NewSessionApprovals() *SessionApprovals {
	return &SessionApprovals{approved: map[string]bool{}}
}

// Approved reports whether the exact command was approved this session.
func (s *SessionApprovals) Approved(c Command) bool { return s.approved[Signature(c)] }

// Remember records the exact command as approved.
func (s *SessionApprovals) Remember(c Command) { s.approved[Signature(c)] = true }

// Signature is the canonical exact signature of a command: the binary and every
// argument joined with a NUL that cannot appear in a validated command.
func Signature(c Command) string {
	return c.Binary + "\x00" + strings.Join(c.Args, "\x00")
}
