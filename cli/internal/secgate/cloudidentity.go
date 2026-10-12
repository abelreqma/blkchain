package secgate

import "strings"

type CloudIdentity struct {
	Provider       string `json:"provider"`
	CredentialFile string `json:"credential_file"`
	TaskID         string `json:"task_id"`
	EvidenceID     int64  `json:"evidence_id"`
	At             string `json:"at"`
}

func (g *Gate) cloudIdentityCommand(c Command) bool {
	if g == nil || g.Policy == nil || !g.EffectiveFoothold().Covers(c.Surface) {
		return false
	}
	identity, ok := g.CloudIdentities[c.Surface]
	if !ok || identity.CredentialFile == "" {
		return false
	}
	switch c.Surface {
	case SurfaceCloudAWS:
		return identity.Provider == "aws" && c.Binary == "aws"
	case SurfaceCloudGCP:
		return identity.Provider == "gcp" && c.Binary == "gcloud"
	}
	return false
}

func cloudIdentityViolation(c Command) string {
	for _, arg := range c.Args {
		name, _, _ := strings.Cut(strings.ToLower(arg), "=")
		if c.Surface == SurfaceCloudAWS {
			switch name {
			case "--profile", "--endpoint-url", "--no-sign-request", "--debug":
				return "cloud identity override is not permitted: " + name
			}
			if name == "configure" || name == "sso" {
				return "aws command changes the approved identity"
			}
		}
		if c.Surface == SurfaceCloudGCP {
			switch name {
			case "--account", "--impersonate-service-account", "--access-token-file", "--credential-file-override", "--flags-file", "--configuration", "--log-http", "--trace-token", "--verbosity":
				return "cloud identity override is not permitted: " + name
			}
		}
	}
	if c.Surface == SurfaceCloudGCP {
		for _, arg := range c.Args {
			switch strings.ToLower(arg) {
			case "auth", "config", "components", "alpha", "beta", "ssh", "scp", "start-iap-tunnel":
				return "gcloud command changes identity or opens an unbounded execution channel"
			}
		}
	}
	if !c.Phase.requiresArm() && !cloudReadOnly(c) {
		return "credentialed cloud operation requires an armed exploit or post-ex task"
	}
	return ""
}

func cloudReadOnly(c Command) bool {
	if c.Surface == SurfaceCloudAWS {
		if len(c.Args) < 2 || strings.HasPrefix(c.Args[0], "-") || strings.HasPrefix(c.Args[1], "-") {
			return false
		}
		op := strings.ToLower(c.Args[1])
		for _, prefix := range []string{"describe-", "list-", "get-", "head-", "lookup-", "search-"} {
			if strings.HasPrefix(op, prefix) {
				return true
			}
		}
		return false
	}
	if c.Surface == SurfaceCloudGCP {
		if len(c.Args) >= 2 {
			switch strings.Join(c.Args[:2], " ") {
			case "projects list", "projects describe", "services list":
				return true
			}
		}
		if len(c.Args) >= 3 {
			switch strings.Join(c.Args[:3], " ") {
			case "compute instances list", "compute instances describe", "iam service-accounts list", "storage buckets list":
				return true
			}
		}
	}
	return false
}
