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

// externalEngageAllowlist is the EXTERNAL-profile allowlist: network and
// enumeration tools only. It deliberately excludes host-introspection/read
// utilities (id, whoami, uname, hostname, ps, ls, cat, head, tail, grep, stat,
// getcap, ss, netstat, ip, ifconfig). In external /auto, a read utility with an
// in-scope host operand and a file operand would otherwise disclose the file:
// the scope check passes on the host operand, and FileAccessViolation does not
// cover cat/grep. Keeping them off the external allowlist closes that
// disclosure with the smallest surface. They remain usable in the LOCAL
// profile, which has no allowlist (ClassifyLocal governs) and requires
// per-command human confirmation for every command.
//
// Shells, wrappers, and interpreters (sudo, env, bash, sh, python, find,
// xargs) stay excluded here too: secgate's classifier denies them outright
// regardless of the allowlist, so listing them would only be misleading. An
// operator who needs one of those tools runs it by hand, outside run_command.
func externalEngageAllowlist() []string {
	return []string{
		"nmap", "curl", "wget", "dig", "whois", "nc", "ncat",
		// DNS enumeration. Each has a flag audit in secgate (see
		// secgate/dnsenum_test.go); host and nslookup have no file, exec, or
		// config flag, dnsrecon's file flags are bounded in FileAccessViolation.
		"host", "nslookup", "dnsrecon",
		// SMB, RPC, NetBIOS, and NFS enumeration. Audited in
		// secgate/smbenum_test.go: -c/--command, config and credential files, and
		// nbtscan -f are denied, log paths are bounded, glued host flags are
		// denied, and a UNC host is scope-checked.
		"smbclient", "rpcclient", "nbtscan", "showmount",
		// LDAP, SNMP, and HTTP discovery. Audited in secgate/netenum_test.go and
		// secgate/httpenum_test.go: exec and plugin flags, config and credential
		// files, and file-of-targets flags are denied, output and wordlist paths
		// are bounded, glued target flags are denied, and every target flag value
		// must resolve to a host the scope check can see.
		"ldapsearch", "snmpwalk", "onesixtyone", "gobuster", "ffuf", "nikto",
	}
}

type gatePolicy struct {
	DeniedBinaries      []string
	UnattendedAllow     *secgate.Allowlist
	AllowInterpreterPoC bool
	AutoScopeOverride   bool
}

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
	return &secgate.Gate{
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
		},
		Scratch:             scratch,
		ConfigDenied:        policy.DeniedBinaries,
		UnattendedAllow:     policy.UnattendedAllow,
		AllowInterpreterPoC: policy.AllowInterpreterPoC,
		AutoScopeOverride:   policy.AutoScopeOverride,
	}
}

// buildEngageDeps assembles the engageDeps fields shared by blk engage and the
// MCP engage tool. asker, confirmer, and progress are caller-specific: they
// are passed straight through rather than decided here. engagecmd picks a
// terminal asker and confirmer on a TTY and wires a live progress renderer;
// the MCP tool uses an AutoAsker, an elicit confirmer (or none for /auto), and
// no progress callback.
func buildEngageDeps(model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, store *engagement.Store, gate *secgate.Gate, workDir string, catalog *skillcat.Catalog, asker askuser.Asker, confirmer secgate.Confirmer, progress func(rev int64, snap engagement.Engagement)) engageDeps {
	return engageDeps{
		Model:     model,
		RC:        rc,
		Cfg:       cfg,
		Prefs:     prefs,
		Store:     store,
		Asker:     asker,
		Gate:      gate,
		Confirmer: confirmer,
		Runs:      NewRunOutputs(),
		WorkDir:   workDir,
		Catalog:   catalog,
		Progress:  progress,
	}
}
