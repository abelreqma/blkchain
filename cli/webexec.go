package main

import "blkchain/cli/internal/engagement"

// webexec.go is the web-surface executor: a WSTG-aligned recon tier ladder
// for the web surface, registered through the shared seams (registerExecutor,
// registerLadder).
//
// The ladder rests entirely on the already-allowlisted external tools (curl and
// nmap for liveness/TLS/version, gobuster/ffuf/nikto for content and parameter
// discovery), so this file introduces no secgate change. Code owns the ladder;
// the corpus (route_skill "web" + kb_search, both read-only and already wired
// into the recon tool set) only informs the technique chosen within a tier.
//
// webExecutor embeds genericExecutor to reuse the whole live recon machinery:
// the vantage reachability check, the gated tool set (run_command with
// help-grounding, verified record_evidence), the bounded tier loop (ReconLoop,
// which reads this surface's ladder via ladderFor), the LLM sufficiency grader,
// and the code-owned evidence capture + correlation that stamp each finding with
// its Provenance{TaskID, EvidenceID}. In-scope host enforcement lives in the
// gate and is respected here, not reimplemented: every proposed command is
// scope-checked and the target argument is resolve-and-pinned at exec time
// (secgate recheck). One known limitation, not introduced here: a curl
// subprocess that follows an HTTP redirect at runtime is not re-intercepted by
// the gate (the gate pins only the initial target argument), so per-hop redirect
// re-validation on the run_command path is not yet implemented; the gated browser
// tool is where live redirect handling is re-checked. Web-shaped endpoint/param
// correlation (candidate Surface=web, endpoint+param+class) is not emitted here;
// this executor delivers the WSTG-aligned ladder and corpus-grounded recon.

// webLadder is the web surface's recon tier ladder, aligned to the OWASP
// WSTG recon workflow:
//   - T0 liveness-fingerprint: host is up, server/framework fingerprint, and TLS
//     posture (WSTG-INFO-02 fingerprint web server, CRYP-01 weak TLS, CONF-07
//     HSTS) via curl and nmap.
//   - T1 content-discovery: directories, files, and unreferenced/backup content
//     (WSTG-INFO-04 enumerate applications, CONF-03 file-extension handling,
//     CONF-04 old backup and unreferenced files) via gobuster/ffuf/nikto.
//   - T2 param-discovery: application entry points and parameters (WSTG-INFO-06
//     identify entry points) via ffuf and curl.
//   - T3 finding-driven-probes: targeted WSTG vulnerability probes chosen from
//     the findings so far (INPV/ATHZ/SESS families), corpus-grounded.
//
// The tiers, their order, and their coverage dimensions are fixed here; the LLM
// only proposes structured commands within the current tier.
var webLadder = reconLadder{
	{Index: 0, Name: "liveness-fingerprint", Dimensions: []string{"liveness", "server", "tls"}},
	{Index: 1, Name: "content-discovery", Dimensions: []string{"content", "paths"}},
	{Index: 2, Name: "param-discovery", Dimensions: []string{"params", "endpoints"}},
	{Index: 3, Name: "finding-driven-probes", Dimensions: []string{"probes"}},
}

// webExecutor is the web-surface executor. It embeds genericExecutor and adds
// no behavior of its own: the generic Run drives the recon tier loop against
// webLadder (via ladderFor) and keeps every gate, scope, help-grounding,
// evidence, and correlation guarantee. The persona is selected per task by
// domainFor(task.Kind), not by the executor: a web-kind task ("web") gets the
// web (OWASP WSTG) persona, while a recon-phase web-surface task whose Kind is
// "recon" gets the recon persona - both appropriate, since the executor is chosen
// by Surface and the persona by Kind. The distinct type marks the surface as
// implemented (executorFor returns it, not the generic fallback) and is the seam
// the gated browser-automation tool extends on its own branch.
type webExecutor struct {
	genericExecutor
}

func init() {
	registerExecutor(engagement.SurfaceWeb, func(d engageDeps) surfaceExecutor {
		return webExecutor{genericExecutor{d: d}}
	})
	registerLadder(engagement.SurfaceWeb, webLadder)
}
