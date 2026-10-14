package main

import (
	"path/filepath"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

type observedReconAction struct {
	command secgate.Command
	result  runResult
}

func tierOutcomeFromSignals(tier reconTier, commandDelta, evidenceDelta int) tierOutcome {
	out := tierOutcome{Commands: commandDelta}
	if evidenceDelta > 0 {
		out.DimensionsCovered = tier.Dimensions
	}
	return out
}

func tierOutcomeFromActions(surface engagement.Surface, tier reconTier, commandDelta, evidenceDelta int, actions []observedReconAction) tierOutcome {
	if surface != engagement.SurfaceNetwork {
		return tierOutcomeFromSignals(tier, commandDelta, evidenceDelta)
	}
	out := tierOutcome{Commands: commandDelta}
	covered := make(map[string]bool)
	for _, action := range actions {
		if action.result.Err != nil || action.result.TimedOut || action.result.ExitCode != 0 || strings.TrimSpace(action.result.Output) == "" {
			continue
		}
		c := action.command
		name := strings.ToLower(filepath.Base(c.Binary))
		if name == "nmap" && !nmapFinished(action.result.Output) {
			continue
		}
		if name == "nmap" && tier.Index > 0 && !nmapHostUp(action.result.Output) {
			continue
		}
		switch tier.Index {
		case 0:
			if name == "nmap" {
				covered["hosts"] = true
			}
		case 1:
			if name != "nmap" || nmapServiceScan(c.Args) || nmapDiagnostic(c.Args) {
				continue
			}
			for _, ep := range scanPortSpec(c.Args, nmapDefaultTransport(c.Args)) {
				if ep.transport == "tcp" {
					covered["tcp-sweep"] = true
				} else {
					covered["udp-sweep"] = true
				}
			}
		case 2:
			if name != "nmap" || nmapDiagnostic(c.Args) {
				continue
			}
			for _, arg := range c.Args {
				if arg == "-A" || strings.HasPrefix(arg, "-s") && strings.Contains(arg[2:], "V") {
					covered["versions"] = true
				}
				if arg == "-A" || strings.HasPrefix(arg, "-s") && strings.Contains(arg[2:], "C") {
					covered["safe-scripts"] = true
				}
			}
		case 3:
			if name == "nmap" || name == "nping" && !npingHasPayload(c.Args) {
				continue
			}
			endpoints, discovery, err := serviceRequirement(c)
			if err == nil && !discovery && len(endpoints) > 0 {
				covered["probes"] = true
			}
		}
	}
	for _, dim := range tier.Dimensions {
		if covered[dim] {
			out.DimensionsCovered = append(out.DimensionsCovered, dim)
		}
	}
	return out
}

func npingHasPayload(args []string) bool {
	for _, arg := range args {
		if arg == "--data" {
			return true
		}
	}
	return false
}
