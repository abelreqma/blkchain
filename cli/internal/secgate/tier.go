package secgate

// Phase is the engagement phase a command belongs to. It mirrors
// engagement.Phase by string value; the gate derives the per-command tier from
// it (tier = f(surface, phase, armed), derived at gate time, never stored).
type Phase string

const (
	PhaseRecon   Phase = "recon"
	PhaseExploit Phase = "exploit"
	PhasePostEx  Phase = "post-ex"
	PhaseReport  Phase = "report"
)

// Surface is the attack surface a command targets. It mirrors
// engagement.Surface by string value; it is informational for the tier today.
type Surface string

const (
	SurfaceLocal   Surface = "local"
	SurfaceNetwork Surface = "network"
	SurfaceWeb     Surface = "web"
	SurfaceADCloud Surface = "ad-cloud"
)

// requiresArm reports whether a command in this phase may run only when its task
// is armed. Exploit and post-ex require arming; recon and report (and any empty
// or unknown phase, which fail safe to the recon posture) do not.
func (p Phase) requiresArm() bool {
	return p == PhaseExploit || p == PhasePostEx
}

// perActionConfirm reports whether this phase forces per-action human
// confirmation regardless of mode (the exploit/post-ex confirm tier).
func (p Phase) perActionConfirm() bool {
	return p == PhaseExploit || p == PhasePostEx
}
