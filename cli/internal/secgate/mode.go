package secgate

// Mode is the autonomy mode: Safe (confirm every command) or Auto (bounded,
// requires a scope).
type Mode int

const (
	Safe Mode = iota
	Auto
)

// String returns the mode name.
func (m Mode) String() string {
	if m == Auto {
		return "auto"
	}
	return "safe"
}
