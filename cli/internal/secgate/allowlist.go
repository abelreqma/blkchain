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

// EditConfirmer is a Confirmer that may also return an operator-edited substitute
// command to run instead of the one presented. When edited is non-nil (and allow
// is true), the gate re-validates the substitute through the FULL deny pipeline
// (classifier, scope, denylists, tier) with the ORIGINAL command's Phase/Surface/
// Armed preserved, and executes it only if that passes; the operator cannot use an
// edit to change the tier or bypass a denylist. edited == nil runs the original.
// A Confirmer that does not implement this is used as a plain bool confirmer.
type EditConfirmer interface {
	Confirmer
	ConfirmOrEdit(ctx context.Context, c Command) (allow bool, edited *Command)
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
