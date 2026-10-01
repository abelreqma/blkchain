package secgate

type Command struct {
	Binary string
	Args   []string

	Phase   Phase
	Surface Surface
	Armed   bool
}

// Decision is the gate's verdict for one command. Suggestion is a bounded
// alternative when a structural rule tripped; it may be empty.
type Decision struct {
	Allowed    bool
	Reason     string
	Suggestion string
}
