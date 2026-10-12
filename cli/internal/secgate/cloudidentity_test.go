package secgate

import (
	"context"
	"strings"
	"testing"
)

func TestCloudCLIRequiresApprovedIdentityAndFootholdSurface(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("203.0.113.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Foothold = &Foothold{Host: "203.0.113.10", Surfaces: []Surface{SurfaceCloudAWS, SurfaceCloudGCP}}
	g := &Gate{Mode: Auto, Scope: scope, Policy: p, Allow: NewAllowlist()}
	aws := Command{Binary: "aws", Args: []string{"sts", "get-caller-identity"}, Surface: SurfaceCloudAWS, Phase: PhaseRecon}
	gcp := Command{Binary: "gcloud", Args: []string{"projects", "list"}, Surface: SurfaceCloudGCP, Phase: PhaseRecon}
	for _, c := range []Command{aws, gcp} {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Fatalf("unapproved %s command allowed", c.Binary)
		}
	}
	g.CloudIdentities = map[Surface]CloudIdentity{
		SurfaceCloudAWS: {Provider: "aws", CredentialFile: "/var/keys/aws"},
		SurfaceCloudGCP: {Provider: "gcp", CredentialFile: "/var/keys/gcp.json"},
	}
	for _, c := range []Command{aws, gcp} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("approved %s command denied: %s", c.Binary, d.Reason)
		}
	}
	for _, c := range []Command{
		{Binary: "aws", Args: []string{"sts", "get-caller-identity"}, Surface: SurfaceWeb, Phase: PhaseRecon},
		{Binary: "./aws", Args: []string{"sts", "get-caller-identity"}, Surface: SurfaceCloudAWS, Phase: PhaseRecon},
		{Binary: "aws", Args: []string{"--profile", "other", "sts", "get-caller-identity"}, Surface: SurfaceCloudAWS, Phase: PhaseRecon},
		{Binary: "aws", Args: []string{"--debug", "sts", "get-caller-identity"}, Surface: SurfaceCloudAWS, Phase: PhaseRecon},
		{Binary: "aws", Args: []string{"configure", "list"}, Surface: SurfaceCloudAWS, Phase: PhaseRecon},
		{Binary: "aws", Args: []string{"iam", "create-user", "--user-name", "fixture"}, Surface: SurfaceCloudAWS, Phase: PhaseRecon},
		{Binary: "gcloud", Args: []string{"--impersonate-service-account=x", "projects", "list"}, Surface: SurfaceCloudGCP, Phase: PhaseRecon},
		{Binary: "gcloud", Args: []string{"--log-http", "projects", "list"}, Surface: SurfaceCloudGCP, Phase: PhaseRecon},
		{Binary: "gcloud", Args: []string{"projects", "create", "fixture"}, Surface: SurfaceCloudGCP, Phase: PhaseRecon},
		{Binary: "gcloud", Args: []string{"projects", "create", "list"}, Surface: SurfaceCloudGCP, Phase: PhaseRecon},
		{Binary: "gcloud", Args: []string{"config", "set", "account", "other"}, Surface: SurfaceCloudGCP, Phase: PhaseRecon},
	} {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("identity override or wrong surface allowed: %s %v", c.Binary, c.Args)
		}
	}
}
