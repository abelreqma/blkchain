package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/skillcat"
)

func engagementDeltaAddT1(t *testing.T) engagement.Delta {
	t.Helper()
	return engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Status: engagement.StatusTodo}}, Kind: "init"}
}

func writeTestSkill(t *testing.T, dir, name, body string) {
	t.Helper()
	d := dir + "/" + name
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d+"/SKILL.md", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRouteSkillDeliversAndRecordsReceipt(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "abusing-adcs", "---\nname: abusing-adcs\ndescription: AD CS kerberos abuse\n---\n# ADCS\nenumerate first\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t) // from plantools_test.go
	if _, err := st.Apply(engagementDeltaAddT1(t)); err != nil {
		t.Fatal(err)
	}
	tool := newRouteSkillTool(cat, st, func() string { return "t1" })
	out, err := tool.Call(context.Background(), `{"domain":"ad"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "abusing-adcs") || !strings.Contains(out, "enumerate first") {
		t.Errorf("route output missing skill: %q", out)
	}
	rc, _ := st.ReceiptsFor("t1")
	if len(rc) != 1 || rc[0].Skill != "abusing-adcs" {
		t.Errorf("receipt not recorded: %+v", rc)
	}
}

func TestRouteSkillNoSkillForDomain(t *testing.T) {
	cat, err := skillcat.Load("") // empty dir: documented to be a no-error empty catalog
	if err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	st := openStore(t)
	tool := newRouteSkillTool(cat, st, func() string { return "" })
	out, err := tool.Call(context.Background(), `{"domain":"web"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "no skill") {
		t.Errorf("want a clean no-skill message, got %q", out)
	}
}

// TestRouteSkillGarbageDomainNeverSelectsNamedSkill is the security regression
// guard: the model supplies only a domain or keyword, so a crafted string with
// no keyword (a path traversal string, empty) must never deliver a specific
// named skill from another bucket. It falls back to the generic bucket.
// Keyword-bearing crafted strings are covered by
// TestRouteSkillKeywordNeverPinsSkillByName.
func TestRouteSkillGarbageDomainNeverSelectsNamedSkill(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "attacking-oauth", "---\nname: attacking-oauth\ndescription: oauth jwt web attacks\n---\nWEB PLAYBOOK BODY\n")
	writeTestSkill(t, dir, "zzz-generic", "---\nname: zzz-generic\ndescription: unrelated notes\n---\nGENERIC PLAYBOOK BODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t)
	tool := newRouteSkillTool(cat, st, func() string { return "" })
	// Each crafted domain has no keyword, so it must resolve to the generic
	// bucket, never the named web skill.
	for _, dom := range []string{"../../etc/passwd", "zzznotathing", ""} {
		args := `{"domain":` + jsonQuote(dom) + `}`
		out, err := tool.Call(context.Background(), args)
		if err != nil {
			t.Fatalf("domain=%q: unexpected error %v", dom, err)
		}
		if strings.Contains(out, "attacking-oauth") || strings.Contains(out, "WEB PLAYBOOK BODY") {
			t.Errorf("domain=%q leaked the named web skill: %q", dom, out)
		}
		if !strings.Contains(out, "zzz-generic") {
			t.Errorf("domain=%q did not fall back to the generic skill: %q", dom, out)
		}
	}
}

// keywordCatalog loads one skill per domain, each named s-<domain>, so a routed
// skill name identifies the bucket it came from.
func keywordCatalog(t *testing.T) *skillcat.Catalog {
	t.Helper()
	dir := t.TempDir()
	writeTestSkill(t, dir, "s-ad", "---\nname: s-ad\ndescription: kerberos notes\n---\nAD\n")
	writeTestSkill(t, dir, "s-web", "---\nname: s-web\ndescription: web notes\n---\nWEB\n")
	writeTestSkill(t, dir, "s-k8s", "---\nname: s-k8s\ndescription: kubernetes notes\n---\nK8S\n")
	writeTestSkill(t, dir, "s-generic", "---\nname: s-generic\ndescription: unrelated notes\n---\nGENERIC\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestResolveDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		// exact domain names, case and space insensitive
		{"ad", "ad"}, {"web", "web"}, {"generic", "generic"},
		{"GENERIC", "generic"}, {" ad ", "ad"}, {"  Web ", "web"},
		// vuln-class keywords fall back through DeriveDomain
		{"kerberos", "ad"}, {"adcs", "ad"}, {"xss", "web"},
		{"api", "web"}, {"oauth", "web"}, {"container", "k8s"},
		// no keyword stays generic
		{"../../etc/passwd", "generic"}, {"zzznotathing", "generic"}, {"random", "generic"}, {"", "generic"},
	}
	for _, c := range cases {
		if got := resolveDomain(c.in); got != c.want {
			t.Errorf("resolveDomain(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestRouteSkillForKeywordRoutesToDomainBucket(t *testing.T) {
	cat := keywordCatalog(t)
	cases := []struct{ in, want string }{
		{"kerberos", "s-ad"}, {"adcs", "s-ad"}, {"xss", "s-web"},
		{"container", "s-k8s"}, {"api", "s-web"},
		{"ad", "s-ad"}, {"web", "s-web"}, {"generic", "s-generic"},
		{"GENERIC", "s-generic"}, {" ad ", "s-ad"},
		{"../../etc/passwd", "s-generic"}, {"zzznotathing", "s-generic"}, {"random", "s-generic"}, {"", "s-generic"},
	}
	for _, c := range cases {
		sk, ok := routeSkillFor(cat, c.in)
		if !ok || sk.Name != c.want {
			t.Errorf("routeSkillFor(%q) = %q,%v; want %q,true", c.in, sk.Name, ok, c.want)
		}
	}
}

// TestRouteSkillKeywordNeverPinsSkillByName proves the no-pin invariant: a
// caller passing a skill's own name (which carries a keyword) reaches only the
// domain bucket and gets the name-sorted first skill, not the named one.
func TestRouteSkillKeywordNeverPinsSkillByName(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: web http attacks\n---\nABODY\n")
	writeTestSkill(t, dir, "attacking-oauth", "---\nname: attacking-oauth\ndescription: oauth jwt web attacks\n---\nOBODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, dom := range []string{"attacking-oauth", "web/../ad", "web\x00"} {
		sk, ok := routeSkillFor(cat, dom)
		if !ok || sk.Name != "aaa-web" {
			t.Errorf("routeSkillFor(%q) = %q,%v; want aaa-web,true (bucket first, never the named skill)", dom, sk.Name, ok)
		}
	}
}

// TestRouteSkillNoSkillMessageNamesResolvedDomain checks both not-found sites
// report the resolved domain, not the raw keyword or a generic fallback.
func TestRouteSkillNoSkillMessageNamesResolvedDomain(t *testing.T) {
	cat, err := skillcat.Load("") // empty dir: documented to be a no-error empty catalog
	if err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	tool := newRouteSkillTool(cat, openStore(t), func() string { return "" })
	out, err := tool.Call(context.Background(), `{"domain":"kerberos"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "domain ad") {
		t.Errorf("tool message should name resolved domain ad, got %q", out)
	}
	res := mcpRouteResult(cat, "kerberos")
	if res["found"] != false || res["domain"] != "ad" {
		t.Errorf("mcpRouteResult not-found should name resolved domain ad, got %v", res)
	}
}

func TestRouteSkillTruncatesLongBody(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("a", routeSkillBodyCap+100)
	writeTestSkill(t, dir, "long-web", "---\nname: long-web\ndescription: web http attacks\n---\n"+long+"\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tool := newRouteSkillTool(cat, openStore(t), func() string { return "" })
	out, err := tool.Call(context.Background(), `{"domain":"web"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "truncated") {
		t.Errorf("long body was not marked truncated: len=%d", len(out))
	}
}

func TestRouteSkillNoReceiptWhenNoActiveTask(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "some-web", "---\nname: some-web\ndescription: web http attacks\n---\nbody\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t)
	if _, err := st.Apply(engagementDeltaAddT1(t)); err != nil {
		t.Fatal(err)
	}
	tool := newRouteSkillTool(cat, st, func() string { return "" }) // empty active task
	if _, err := tool.Call(context.Background(), `{"domain":"web"}`); err != nil {
		t.Fatal(err)
	}
	rc, _ := st.ReceiptsFor("t1")
	if len(rc) != 0 {
		t.Errorf("no receipt expected when active task is empty, got %d", len(rc))
	}
}

// jsonQuote renders s as a JSON string literal for building a test args payload.
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestRouteSkillForSelectsNameSortedFirst(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "zzz-web", "---\nname: zzz-web\ndescription: web http attacks\n---\nZBODY\n")
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: web http attacks\n---\nABODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := routeSkillFor(cat, "web")
	if !ok || sk.Name != "aaa-web" {
		t.Errorf("routeSkillFor(web) = %q,%v; want aaa-web,true", sk.Name, ok)
	}
	// Unknown domain resolves to generic; empty catalog bucket -> not found.
	if _, ok := routeSkillFor(cat, "../../etc/passwd"); ok {
		t.Errorf("garbage domain must not find a skill (no generic skill present)")
	}
	if _, ok := routeSkillFor(nil, "web"); ok {
		t.Errorf("nil catalog must return not-found")
	}
}
