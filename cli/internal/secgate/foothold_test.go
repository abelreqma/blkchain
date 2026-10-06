package secgate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseFootholdSSH(t *testing.T) {
	f, err := ParseFoothold("10.10.5.21 transport=ssh user=svc-deploy key=$BLKCHAIN_FOOTHOLD_KEY")
	if err != nil {
		t.Fatalf("ParseFoothold: %v", err)
	}
	if f.Host != "10.10.5.21" || f.Transport != "ssh" || f.User != "svc-deploy" || f.Key != "$BLKCHAIN_FOOTHOLD_KEY" {
		t.Fatalf("parsed = %+v", f)
	}
	if len(f.Surfaces) != 1 || f.Surfaces[0] != SurfaceLocal {
		t.Errorf("default surfaces = %v, want [local]", f.Surfaces)
	}
	if f.CarrierBinary() != "ssh" {
		t.Errorf("CarrierBinary() = %q, want ssh", f.CarrierBinary())
	}
}

// TestParseFootholdDefaultsToSSH pins that omitting transport= selects ssh, so
// the shortest declaration is the common one rather than an error.
func TestParseFootholdDefaultsToSSH(t *testing.T) {
	f, err := ParseFoothold("10.0.0.9 user=root key=/keys/id_ed25519")
	if err != nil {
		t.Fatalf("ParseFoothold: %v", err)
	}
	if f.Transport != "ssh" {
		t.Errorf("Transport = %q, want ssh", f.Transport)
	}
}

// TestParseFootholdExecTakesRemainder pins the grammar rule that lets an argv
// prefix carry spaces with no quoting: exec consumes the rest of the line.
func TestParseFootholdExecTakesRemainder(t *testing.T) {
	f, err := ParseFoothold("web-0.cluster.internal transport=command surfaces=local,container exec=kubectl exec -i web-0 --")
	if err != nil {
		t.Fatalf("ParseFoothold: %v", err)
	}
	want := []string{"kubectl", "exec", "-i", "web-0", "--"}
	if strings.Join(f.Exec, " ") != strings.Join(want, " ") {
		t.Fatalf("Exec = %v, want %v", f.Exec, want)
	}
	if !f.Covers(SurfaceLocal) || !f.Covers(SurfaceContainer) {
		t.Errorf("Covers local=%t container=%t, want both true", f.Covers(SurfaceLocal), f.Covers(SurfaceContainer))
	}
	if f.Covers(SurfaceWeb) {
		t.Error("Covers(web) = true for an undeclared surface")
	}
	if f.CarrierBinary() != "kubectl" {
		t.Errorf("CarrierBinary() = %q, want kubectl", f.CarrierBinary())
	}
}

// TestNilFootholdCoversNothing pins the fail-closed default: with no foothold
// declared, no surface pivots and the sandbox worker stays the destination.
func TestNilFootholdCoversNothing(t *testing.T) {
	var f *Foothold
	for _, s := range footholdSurfaces {
		if f.Covers(s) {
			t.Errorf("nil foothold covers %s", s)
		}
	}
	if f.CarrierBinary() != "" {
		t.Errorf("nil CarrierBinary() = %q, want empty", f.CarrierBinary())
	}
}

func TestParseFootholdRejects(t *testing.T) {
	cases := []struct {
		name, entry, want string
	}{
		{"empty", "", "empty foothold entry"},
		{"setting first", "transport=ssh 10.0.0.1", "must begin with a host"},
		{"bad host", "bad!host user=x key=k", "is not an IP or hostname"},
		{"host with port", "10.0.0.1:22 user=x key=k", "is not an IP or hostname"},
		{"cidr host", "10.0.0.0/24 user=x key=k", "is not an IP or hostname"},
		{"bare setting", "10.0.0.1 transport", "is not key=value"},
		{"empty value", "10.0.0.1 user=", "has an empty value"},
		{"unknown setting", "10.0.0.1 shell=bash", "unknown foothold setting"},
		{"unknown transport", "10.0.0.1 transport=telnet user=x key=k", "is not one of"},
		{"unknown surface", "10.0.0.1 user=x key=k surfaces=web", "is not one of"},
		{"bad port", "10.0.0.1 user=x key=k port=70000", "is not 1-65535"},
		{"bad env name", "10.0.0.1 user=x key=k env=9BAD", "not a valid environment variable name"},
		{"ssh without user", "10.0.0.1 transport=ssh key=k", "requires user="},
		{"ssh without key", "10.0.0.1 transport=ssh user=x", "requires key="},
		{"ssh with exec", "10.0.0.1 transport=ssh user=x key=k exec=sh", "does not take exec="},
		{"command without exec", "10.0.0.1 transport=command", "requires exec="},
		{"command with path", "10.0.0.1 transport=command exec=/bin/sh -c", "bare binary name"},
		{"command with ssh keys", "10.0.0.1 transport=command user=x exec=kubectl", "takes only exec="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseFoothold(tc.entry)
			if err == nil {
				t.Fatalf("ParseFoothold(%q) = %+v, want error", tc.entry, f)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestFootholdInScope(t *testing.T) {
	scope, err := BuildScope(ScopeSpec{In: []string{"10.10.5.0/24", "jump.example.com", "*.cluster.internal"}})
	if err != nil {
		t.Fatalf("BuildScope: %v", err)
	}
	cases := []struct {
		name, host string
		ok         bool
	}{
		{"ip covered by cidr", "10.10.5.21", true},
		{"ip outside cidr", "10.99.0.1", false},
		{"explicit hostname", "jump.example.com", true},
		{"wildcard-only hostname", "web-0.cluster.internal", false},
		{"unlisted hostname", "other.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Foothold{Host: tc.host, Transport: "ssh", User: "u", Key: "k", Surfaces: []Surface{SurfaceLocal}}
			err := FootholdInScope(scope, f)
			if tc.ok && err != nil {
				t.Fatalf("FootholdInScope(%s) = %v, want nil", tc.host, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("FootholdInScope(%s) = nil, want an error", tc.host)
			}
		})
	}
	if err := FootholdInScope(nil, nil); err != nil {
		t.Errorf("FootholdInScope(nil, nil) = %v, want nil", err)
	}
	f := &Foothold{Host: "10.10.5.21", Transport: "ssh", User: "u", Key: "k"}
	if err := FootholdInScope(nil, f); err == nil {
		t.Error("FootholdInScope with a nil scope = nil, want an error")
	}
}

// TestFootholdOutOfScopeWins pins that an out-of-scope entry overriding an
// in-scope CIDR also rejects the foothold, so an excluded host cannot be
// reached through the pivot.
func TestFootholdOutOfScopeWins(t *testing.T) {
	scope, err := BuildScope(ScopeSpec{In: []string{"10.10.5.0/24"}, Out: []string{"10.10.5.21"}})
	if err != nil {
		t.Fatalf("BuildScope: %v", err)
	}
	f := &Foothold{Host: "10.10.5.21", Transport: "ssh", User: "u", Key: "k"}
	if err := FootholdInScope(scope, f); err == nil {
		t.Fatal("an out-of-scope foothold host was accepted")
	}
}

// TestSealedPolicyCarriesFootholdWithoutSecrets pins two properties at once: the
// foothold changes the policy hash, so a resume with a different foothold is
// refused, and no secret value reaches Canonical, which is embedded verbatim in
// the model prompt.
func TestSealedPolicyCarriesFootholdWithoutSecrets(t *testing.T) {
	scope, err := BuildScope(ScopeSpec{In: []string{"10.10.5.21"}})
	if err != nil {
		t.Fatalf("BuildScope: %v", err)
	}
	seal := func(f *Foothold) *Policy {
		p := DefaultPolicy()
		p.Foothold = f
		if err := p.Seal("s", []string{"10.10.5.21"}, scope); err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return p
	}
	bare := seal(nil)
	withFoothold := seal(&Foothold{Host: "10.10.5.21", Transport: "ssh", User: "svc", Key: "$FOOTHOLD_KEY", Env: []string{"FOOTHOLD_PASSPHRASE"}, Surfaces: []Surface{SurfaceLocal}})
	other := seal(&Foothold{Host: "10.10.5.21", Transport: "ssh", User: "root", Key: "$FOOTHOLD_KEY", Surfaces: []Surface{SurfaceLocal}})

	if bare.Hash == withFoothold.Hash {
		t.Error("declaring a foothold did not change the policy hash")
	}
	if withFoothold.Hash == other.Hash {
		t.Error("changing the foothold user did not change the policy hash")
	}
	if !strings.Contains(bare.Canonical, `"allowed_actions"`) {
		t.Fatalf("Canonical is not the policy document: %s", bare.Canonical)
	}
	if strings.Contains(bare.Canonical, "foothold") {
		t.Error("an undeclared foothold still appears in the sealed document")
	}
	// The declaration names secrets; it never holds them. Only the env var name
	// and the key reference as written may appear.
	for _, secret := range []string{"hunter2", "/Users/op/.ssh/id_ed25519", "BEGIN OPENSSH PRIVATE KEY"} {
		if strings.Contains(withFoothold.Canonical, secret) {
			t.Errorf("Canonical leaked %q", secret)
		}
	}
	var doc struct {
		Policy struct {
			Foothold *Foothold `json:"foothold"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(withFoothold.Canonical), &doc); err != nil {
		t.Fatalf("Canonical is not valid JSON: %v", err)
	}
	if doc.Policy.Foothold == nil || doc.Policy.Foothold.User != "svc" {
		t.Fatalf("sealed foothold = %+v", doc.Policy.Foothold)
	}
}
