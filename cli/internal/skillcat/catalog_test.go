package skillcat

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSkill(t *testing.T, dir, name, body string) {
	t.Helper()
	d := filepath.Join(dir, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCatalogAndDomains(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, dir, "abusing-adcs", "---\nname: abusing-adcs\ndescription: AD CS and kerberos abuse\n---\nbody\n")
	writeSkill(t, dir, "attacking-oauth", "---\nname: attacking-oauth\ndescription: OAuth and JWT web attacks\n---\nbody\n")
	writeSkill(t, dir, "broken", "no frontmatter\n")                            // excluded
	writeSkill(t, dir, "dup", "---\nname: abusing-adcs\ndescription: x\n---\n") // duplicate name -> excluded

	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2 (2 valid, 2 excluded)", c.Len())
	}
	if len(c.Errors()) != 2 {
		t.Errorf("want 2 exclusion errors, got %d", len(c.Errors()))
	}
	if _, ok := c.Get("abusing-adcs"); !ok {
		t.Error("abusing-adcs should be present")
	}
	ad := c.ForDomain("ad")
	if len(ad) != 1 || ad[0].Name != "abusing-adcs" {
		t.Errorf("ad domain = %v", ad)
	}
	web := c.ForDomain("web")
	if len(web) != 1 || web[0].Name != "attacking-oauth" {
		t.Errorf("web domain = %v", web)
	}
}

func TestLoadEmptyDirIsNotError(t *testing.T) {
	c, err := Load("")
	if err != nil || c.Len() != 0 {
		t.Errorf("empty dir: err=%v len=%d", err, c.Len())
	}
	c2, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil || c2.Len() != 0 {
		t.Errorf("missing dir should be empty catalog, no error: err=%v len=%d", err, c2.Len())
	}
}

func TestDeriveDomain(t *testing.T) {
	cases := map[string]string{
		"active directory kerberos": "ad",
		"aws s3 iam":                "cloud",
		"kubernetes eks":            "k8s",
		"oauth jwt xss":             "web",
		"buffer overflow shellcode": "exploit-dev",
		"random unrelated text":     "generic",
	}
	for desc, want := range cases {
		if got := DeriveDomain("x", desc); got != want {
			t.Errorf("DeriveDomain(%q) = %q, want %q", desc, got, want)
		}
	}
}

func TestDeriveDomainLocal(t *testing.T) {
	for _, in := range []struct{ name, desc string }{
		{"linux-privesc", "privilege escalation on Linux hosts"},
		{"gtfobins", "abuse SUID and sudo via GTFOBins"},
		{"sudo-abuse", "enumerate sudo -l rights"},
	} {
		if got := DeriveDomain(in.name, in.desc); got != "local" {
			t.Errorf("DeriveDomain(%q,%q) = %q, want local", in.name, in.desc, got)
		}
	}
	// Must not steal existing-domain matches:
	if got := DeriveDomain("recon", "osint and scanning"); got != "recon" {
		t.Errorf("recon skill misrouted to %q", got)
	}
	if got := DeriveDomain("web app", "sqli and xss testing"); got != "web" {
		t.Errorf("web skill misrouted to %q", got)
	}
}

func TestDeriveDomainTargetAnalysis(t *testing.T) {
	for _, in := range []struct{ name, desc string }{
		{"binary-analysis", "analyze an executable as a privesc vector"},
		{"elf-inspection", "inspect ELF binary symbols and mitigations"},
	} {
		if got := DeriveDomain(in.name, in.desc); got != "target-analysis" {
			t.Errorf("DeriveDomain(%q,%q) = %q, want target-analysis", in.name, in.desc, got)
		}
	}
	// Order regression guards: privesc still -> local; exploit still -> exploit-dev; plain gtfobins -> local.
	if got := DeriveDomain("linux-privesc", "privilege escalation and suid"); got != "local" {
		t.Errorf("privesc misrouted to %q", got)
	}
	if got := DeriveDomain("exploit", "shellcode and buffer overflow"); got != "exploit-dev" {
		t.Errorf("exploit-dev misrouted to %q", got)
	}
	if got := DeriveDomain("gtfobins", "abuse SUID and sudo via GTFOBins"); got != "local" {
		t.Errorf("plain gtfobins misrouted to %q", got)
	}
}

// TestDeriveDomainAISecurity pins the ai-security bucket rule: AI/LLM skills route
// to ai-security (not generic), so route_skill("ai-security") has a skill to
// return.
func TestDeriveDomainAISecurity(t *testing.T) {
	for _, in := range []struct{ name, desc string }{
		{"offensive-ai-security", "SKILL: AI Pentest"},
		{"llm-redteam", "prompt injection and jailbreak testing of an LLM"},
		{"ai-security", "AI red team and model extraction"},
	} {
		if got := DeriveDomain(in.name, in.desc); got != "ai-security" {
			t.Errorf("DeriveDomain(%q,%q) = %q, want ai-security", in.name, in.desc, got)
		}
	}
	// Must not steal unrelated matches: a plain web/ad skill still routes as before.
	if got := DeriveDomain("web app", "sqli and xss testing"); got != "web" {
		t.Errorf("web skill misrouted to %q", got)
	}
	if got := DeriveDomain("adcs", "kerberos and ldap abuse"); got != "ad" {
		t.Errorf("ad skill misrouted to %q", got)
	}
}

// When a text matches keywords in more than one rule, the earlier rule in
// domainRules wins. These pin that precedence so reordering the slice is caught.
func TestDeriveDomainMultiKeywordPrecedence(t *testing.T) {
	cases := []struct {
		desc string
		want string
	}{
		{"prompt injection on the web chatbot api", "ai-security"},                   // ai-security (rule 0) over web
		{"kerberos abuse leading to xss on the portal", "ad"},                        // ad over web
		{"pivot through aws into the kubernetes cluster", "cloud"},                   // cloud over k8s
		{"docker breakout on an azure node", "cloud"},                                // cloud over k8s
		{"ldap enumeration plus sqli on the app", "ad"},                              // ad over web
		{"privilege escalation via a vulnerable binary analysis", "target-analysis"}, // target-analysis over local
	}
	for _, c := range cases {
		if got := DeriveDomain("x", c.desc); got != c.want {
			t.Errorf("DeriveDomain(%q) = %q, want %q", c.desc, got, c.want)
		}
	}
}

func TestDeriveDomainWordBoundary(t *testing.T) {
	// Short keywords must not false-match inside unrelated words.
	generic := []string{
		"it breaks under load",  // must not hit k8s via "eks"/"aks"
		"many weeks of testing", // must not hit k8s via "eks"
		"the laws of physics",   // must not hit cloud via "aws"
		"measure the diameter",  // must not hit cloud via "iam"
		"see a therapist",       // must not hit web via "api"
		"the capital city",      // must not hit web via "api"
	}
	for _, desc := range generic {
		if got := DeriveDomain("x", desc); got != "generic" {
			t.Errorf("DeriveDomain(desc=%q) = %q, want generic", desc, got)
		}
	}
	// Hyphenated names must match multi-word keywords.
	if got := DeriveDomain("request-smuggling", ""); got != "web" {
		t.Errorf("request-smuggling name = %q, want web", got)
	}
	if got := DeriveDomain("active-directory-recon", ""); got != "ad" {
		t.Errorf("active-directory name = %q, want ad", got)
	}
	// Real tokens still classify.
	if got := DeriveDomain("eks-privesc", "attack EKS clusters"); got != "k8s" {
		t.Errorf("eks = %q, want k8s", got)
	}
	if got := DeriveDomain("s3-enum", "enumerate s3 buckets"); got != "cloud" {
		t.Errorf("s3 = %q, want cloud", got)
	}
}
