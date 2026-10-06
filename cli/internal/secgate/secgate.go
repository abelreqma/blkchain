// Package secgate is the fail-closed authorization gate every target-touching
// command must pass before execution. It performs NO execution itself; the
// run_command executor calls Gate.Authorize and only runs a command the Decision
// allows. Every layer denies on unknown, unparseable, or ambiguous input.
package secgate

// Command is a parsed, shell-free command: a binary and its literal arguments.
// It is never a shell string; it is built without a shell so no metacharacter
// is ever interpreted.
type Command struct {
	Operation string
	TaskID    string
	Binary    string
	Args      []string
	// InternalProbe separates code-owned help checks in the audit; it does not change authorization.
	InternalProbe bool

	// Phase, Surface, and Armed are the engagement context the gate derives
	// the per-action tier from. The zero value (Phase "" == recon, unarmed) is
	// the default posture a call site that sets none of them gets.
	Phase   Phase
	Surface Surface
	Armed   bool
	// AutonomousWeb marks a web action authorized by an armed task and its RoE.
	// It suppresses per-action confirmation in Auto mode only.
	AutonomousWeb bool

	// PoCIsInterpreter, PoCHash, and PoCBody are interpreter-PoC DISPLAY
	// metadata, filled by the exploit executor for an authorized, scratch-confined
	// interpreter PoC so the human confirmer can show the operator the exact script
	// body and its sha256 before approving. They are PURELY informational: NO gate
	// layer (classifier, scope, tier, destructive/sensitive-path denylists, rate,
	// allowlist) and NO allow/deny decision reads them. The gate's verdict is
	// byte-identical whether they are set or empty; they exist only for the
	// confirmer to render, and the executor caps PoCBody.
	PoCIsInterpreter bool
	PoCHash          string
	PoCBody          string

	// Kind and Target are task-identity context the gate's deny logic READS -
	// the deliberate inverse of the PoC* block above, which no gate layer reads.
	// Kind mirrors engagement.Task.Kind by string value (e.g. "target-analysis")
	// and Target is that task's analysis target path (engagement.Task.Target).
	// They carry the read-only invariant to the gate: a Kind=="target-analysis"
	// command whose resolved binary equals Target is denied outright (see
	// TargetSelfExecViolation, enforced in checkLocked), because a task that exists
	// to INSPECT a binary must never EXECUTE it. The gate verdict DOES change with
	// these set, by design, but only to turn one narrow allow into a deny - never a
	// deny into an allow. Read ONLY by that structural denial; the classifier never
	// reads them (it stays a context-free structural oracle, so the human-confirmed
	// classifier relaxations cannot reach this rule). A zero value (both empty) is
	// the default posture: the rule is inert and a call site that sets neither keeps
	// its current verdict.
	Kind   string
	Target string
}

// Decision is the gate's verdict for one command. Suggestion is a bounded
// alternative when a structural rule tripped; it may be empty.
type Decision struct {
	Allowed    bool
	Reason     string
	Suggestion string
	// Command is the command the caller MUST execute on an allow: the command that
	// was authorized. It equals the input command normally, or an operator-edited
	// substitute that passed a fresh full re-validation (see EditConfirmer). A
	// caller that executes Decision.Command (not the command it passed in) honors an
	// operator edit; a zero Command (empty Binary) means "run the command you passed".
	Command Command
}
