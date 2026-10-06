package main

import (
	"path/filepath"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
)

// engagecompose.go is the single composition root for the engage gate and
// engageDeps, shared by `blk engage` (engagecmd.go) and the MCP engage tool
// (mcpengage.go). It is the one and only place the Protected-paths recipe and
// the allowlist-by-profile split are built, so the two callers cannot drift.

// gatePolicy carries the .blkchain/config.yaml gate policy and the
// auto-scope override into buildEngageGate. A zero gatePolicy is the default
// posture (nil UnattendedAllow runs unattended /auto, no config
// denylist, no interpreter PoC, no override).
type gatePolicy struct {
	RoE                  *RoE
	DeniedBinaries       []string
	UnattendedAllow      *secgate.Allowlist
	LocalUnattendedAllow *secgate.Allowlist
	LocalUnattendedReady bool
	AutoActions          *autoActionPolicy
	AllowInterpreterPoC  bool
	AutoScopeOverride    bool
	MaxActions           int
	WallSeconds          int
	// ExploitTools is the operator's config exploit_tools list. It is not a
	// gate field (the gate does not read it); buildEngageGate ignores it and the
	// engage entrypoints copy it onto engageDeps for the exploit executor.
	ExploitTools []string
}

// buildEngageGate is the single composition root for the engage gate. It
// selects the allowlist by profile: the external allowlist plus the scope's
// `allow <bin>` lines when the scope is not local, and no allowlist at all for
// local (ClassifyLocal governs there; unattended LOCAL needs RoE and config
// allowlists). It also builds the one and only copy of the Protected-paths
// recipe (the engagement's own artifacts, guarded from an executor's file
// arguments in the LOCAL profile) and sets Scratch. The config policy and
// auto-scope override are threaded onto the Gate here. The caller starts the
// returned gate.
func buildEngageGate(ws *engagement.Workspace, scope *secgate.Scope, mode secgate.Mode, confirm secgate.Confirmer, approvals *secgate.SessionApprovals, scratch string, policy gatePolicy, audit func(action, detail string)) *secgate.Gate {
	var allow *secgate.Allowlist
	if scope == nil || !scope.Local() {
		allowBins := externalEngageAllowlist()
		if scope != nil {
			allowBins = append(allowBins, scope.AllowedBins()...)
		}
		allow = secgate.NewAllowlist(allowBins...)
	}

	// LOCAL profile only: guard the engagement's own artifacts from an
	// executor's file arguments. ws.Dir is the absolute workspace dir, so these
	// resolve to the same absolute paths the sensitive-path check compares
	// against. reportPaths and EvidenceDir are the code's own path builders.
	protMD, protJSON := reportPaths(ws.Dir)
	g := &secgate.Gate{
		Policy: func() *secgate.Policy {
			if policy.RoE != nil {
				return policy.RoE.Policy
			}
			return nil
		}(),
		Mode:      mode,
		Scope:     scope,
		Allow:     allow,
		Confirm:   confirm,
		Approvals: approvals,
		Audit:     audit,
		Protected: []string{
			filepath.Join(ws.Dir, "engagement.db"),
			filepath.Join(ws.Dir, "audit.jsonl"),
			ws.EvidenceDir(),
			protMD,
			protJSON,
			filepath.Join(ws.Dir, "checkpoint.json"),
			filepath.Join(ws.Dir, "ROE.md"),
			filepath.Join(ws.Dir, "scope.txt"),
		},
		Scratch:              scratch,
		ConfigDenied:         policy.DeniedBinaries,
		UnattendedAllow:      policy.UnattendedAllow,
		LocalUnattendedAllow: policy.LocalUnattendedAllow,
		AllowInterpreterPoC:  policy.AllowInterpreterPoC,
		AutoScopeOverride:    policy.AutoScopeOverride,
	}
	if policy.AutoActions != nil {
		g.AutoAction = policy.AutoActions.permitsCommand
	}
	return g
}

// buildEngageDeps assembles the engageDeps fields shared by blk engage and the
// MCP engage tool. asker, confirmer, and progress are caller-specific: they
// are passed straight through rather than decided here. engagecmd picks a
// terminal asker and confirmer on a TTY and wires a live progress renderer;
// the MCP tool uses an AutoAsker, an elicit confirmer (or none for /auto), and
// no progress callback.
func buildEngageDeps(model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, store *engagement.Store, gate *secgate.Gate, workDir string, catalog *skillcat.Catalog, asker askuser.Asker, confirmer secgate.Confirmer, progress func(rev int64, snap engagement.Engagement)) engageDeps {
	return engageDeps{
		Model:      model,
		RC:         rc,
		Cfg:        cfg,
		Prefs:      prefs,
		Store:      store,
		Asker:      asker,
		Gate:       gate,
		Confirmer:  confirmer,
		Runs:       NewRunOutputs(),
		WorkDir:    workDir,
		Catalog:    catalog,
		Progress:   progress,
		ReconTiers: true,
	}
}
