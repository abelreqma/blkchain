package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

func TestPolicyHelpGroundingUsesRunnerImageIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("first"), 0700); err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Policy: secgate.DefaultPolicy()}
	hg := newTaskGrounder(&stubCache{data: map[string]toolInterface{}}, g, t.TempDir(), secgate.Command{})
	before := hg.ResolveVersion(path)
	if before != defaultRunnerTag() {
		t.Fatalf("policy help cache used host identity: %q", before)
	}
	if err := os.WriteFile(path, []byte("second"), 0700); err != nil {
		t.Fatal(err)
	}
	if after := hg.ResolveVersion(path); after != before {
		t.Fatalf("host file content changed runner identity: %q to %q", before, after)
	}
}

func TestCloudFootholdHelpCacheUsesApprovalIdentity(t *testing.T) {
	p := secgate.DefaultPolicy()
	p.Foothold = &secgate.Foothold{Host: "203.0.113.10", Surfaces: []secgate.Surface{secgate.SurfaceCloudAWS}}
	g := &secgate.Gate{Policy: p, CloudIdentities: map[secgate.Surface]secgate.CloudIdentity{
		secgate.SurfaceCloudAWS: {Provider: "aws", CredentialFile: "/srv/keys/aws", At: "2026-10-11T00:00:00Z"},
	}}
	hg := newTaskGrounder(&stubCache{data: map[string]toolInterface{}}, g, t.TempDir(), secgate.Command{Surface: secgate.SurfaceCloudAWS})
	got := hg.ResolveVersion("aws")
	if got == defaultRunnerTag() || !strings.Contains(got, p.Foothold.Host) {
		t.Fatalf("cloud help cache used the runner image: %q", got)
	}
	g.CloudIdentities[secgate.SurfaceCloudAWS] = secgate.CloudIdentity{Provider: "aws", At: "2026-10-12T00:00:00Z"}
	other := newTaskGrounder(&stubCache{data: map[string]toolInterface{}}, g, t.TempDir(), secgate.Command{Surface: secgate.SurfaceCloudAWS})
	if other.ResolveVersion("aws") == got {
		t.Fatal("new approval reused the old foothold help cache")
	}
}

func TestIsHelpSideEffectMatchesBaseName(t *testing.T) {
	helpSideEffectBinaries["dangertool"] = true
	t.Cleanup(func() { delete(helpSideEffectBinaries, "dangertool") })

	if !isHelpSideEffect("dangertool") {
		t.Fatal("bare name in the escape-hatch set should match")
	}
	if !isHelpSideEffect("/usr/local/bin/dangertool") {
		t.Fatal("path-qualified binary should match by base name")
	}
	if isHelpSideEffect("safetool") {
		t.Fatal("a binary not in the set must not be flagged")
	}
}

// stubCache is an in-memory toolHelpCache for grounder tests.
type stubCache struct {
	data   map[string]toolInterface
	stored int
}

func (s *stubCache) key(b, v string) string { return b + "\x00" + v }
func (s *stubCache) Lookup(b, v string) (toolInterface, bool, error) {
	i, ok := s.data[s.key(b, v)]
	return i, ok, nil
}
func (s *stubCache) Store(b, v string, i toolInterface) error {
	if s.data == nil {
		s.data = map[string]toolInterface{}
	}
	s.data[s.key(b, v)] = i
	s.stored++
	return nil
}

func newGrounder(c toolHelpCache, cap func(context.Context, string) (string, bool)) *helpGrounder {
	return &helpGrounder{
		Cache:          c,
		Capture:        cap,
		ResolveVersion: func(string) string { return "vtest" },
		Parse:          parseToolHelp,
	}
}

func TestGroundUnknownBinaryReadsHelpAndCaches(t *testing.T) {
	cache := &stubCache{}
	calls := 0
	capFn := func(_ context.Context, bin string) (string, bool) {
		calls++
		return "Usage: nmap\n  -sV: version\n  -p <ports>\n", true
	}
	hg := newGrounder(cache, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "nmap", Args: []string{"-sV", "10.0.0.5"}})
	if oc.Reject {
		t.Fatalf("real flag must not be rejected: %q", oc.Msg)
	}
	if calls != 1 {
		t.Fatalf("expected one help read, got %d", calls)
	}
	if cache.stored != 1 {
		t.Fatalf("interface should be cached once, got %d", cache.stored)
	}
}

func TestGroundHallucinatedFlagRejectedAndReGrounded(t *testing.T) {
	cache := &stubCache{}
	capFn := func(_ context.Context, _ string) (string, bool) {
		return "Usage: nmap\n  -sV: version\n  -p <ports>\n", true
	}
	hg := newGrounder(cache, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "nmap", Args: []string{"--pwn-everything", "10.0.0.5"}})
	if !oc.Reject {
		t.Fatal("a flag absent from help must be rejected")
	}
	if !strings.Contains(oc.Msg, "--pwn-everything") || !strings.Contains(oc.Msg, "-sV") {
		t.Fatalf("reject message must name the bad flag and the real interface: %q", oc.Msg)
	}
}

func TestGroundCachedInterfaceSkipsHelpRead(t *testing.T) {
	cache := &stubCache{}
	_ = cache.Store("nmap", "vtest", toolInterface{Flags: []string{"-sV"}})
	cache.stored = 0
	calls := 0
	capFn := func(_ context.Context, _ string) (string, bool) { calls++; return "", true }
	hg := newGrounder(cache, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "nmap", Args: []string{"-sV", "10.0.0.5"}})
	if oc.Reject || calls != 0 {
		t.Fatalf("cached interface must skip help: reject=%v calls=%d", oc.Reject, calls)
	}
}

func TestGroundEscapeHatchSkips(t *testing.T) {
	helpSideEffectBinaries["sideeffect"] = true
	t.Cleanup(func() { delete(helpSideEffectBinaries, "sideeffect") })
	calls := 0
	capFn := func(_ context.Context, _ string) (string, bool) { calls++; return "", true }
	hg := newGrounder(&stubCache{}, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "sideeffect", Args: []string{"--whatever"}})
	if oc.Reject || oc.Msg != "" || calls != 0 {
		t.Fatalf("escape-hatch binary must skip grounding entirely: %#v calls=%d", oc, calls)
	}
}

func TestGroundCaptureFailFailsOpenWithNote(t *testing.T) {
	capFn := func(_ context.Context, _ string) (string, bool) { return "", false }
	hg := newGrounder(&stubCache{}, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "weirdtool", Args: []string{"--x"}})
	if oc.Reject {
		t.Fatal("a failed help read must fail open, not reject")
	}
	if oc.Msg == "" {
		t.Fatal("a failed help read must carry an advisory note")
	}
}

func TestGroundUnparseableHelpFailsOpenWithNote(t *testing.T) {
	cache := &stubCache{}
	capFn := func(_ context.Context, _ string) (string, bool) { return "\n\t  \n", true }
	hg := newGrounder(cache, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "weirdtool", Args: []string{"--x"}})
	if oc.Reject {
		t.Fatal("unparseable help must fail open, not reject")
	}
	if oc.Msg == "" {
		t.Fatal("unparseable help must carry an advisory note")
	}
	if cache.stored != 1 {
		t.Fatal("an unparseable interface must be cached for this engagement")
	}
}

func TestGroundFailedHelpReadIsCachedAcrossTasks(t *testing.T) {
	cache := openTestCache(t)
	reads := 0
	capture := func(context.Context, string) (string, bool) {
		reads++
		return "", false
	}
	cmd := secgate.Command{Binary: "nmap", Args: []string{"-sV", "127.0.0.1"}}
	for range 3 {
		outcome := newGrounder(cache, capture).ground(context.Background(), cmd)
		if outcome.Reject || outcome.Msg == "" {
			t.Fatalf("missing ungrounded advisory: %+v", outcome)
		}
	}
	if reads != 1 {
		t.Fatalf("help read repeated %d times", reads)
	}
	var count int
	if err := cache.db.QueryRow("SELECT COUNT(*) FROM blk_tool_help WHERE binary = ?", "nmap").Scan(&count); err != nil || count != 0 {
		t.Fatalf("negative cache persisted: count=%d err=%v", count, err)
	}
}

func TestGroundNilReceiverAllows(t *testing.T) {
	var hg *helpGrounder
	if oc := hg.ground(context.Background(), secgate.Command{Binary: "x", Args: []string{"--y"}}); oc.Reject {
		t.Fatal("nil grounder must allow (grounding disabled)")
	}
}

func TestGroundNoFlagsNothingToValidate(t *testing.T) {
	calls := 0
	capFn := func(_ context.Context, _ string) (string, bool) { calls++; return "", true }
	hg := newGrounder(&stubCache{}, capFn)
	oc := hg.ground(context.Background(), secgate.Command{Binary: "nmap", Args: []string{"10.0.0.5"}})
	if oc.Reject || oc.Msg != "" || calls != 0 {
		t.Fatalf("a bare-target command needs no grounding: %#v calls=%d", oc, calls)
	}
}
