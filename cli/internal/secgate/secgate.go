package secgate

type Command struct {
	Binary string
	Args   []string

	Phase   Phase
	Surface Surface
	Armed   bool

	PoCIsInterpreter bool
	PoCHash          string
	PoCBody          string
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
