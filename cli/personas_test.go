package main

import (
	"strings"
	"testing"

	"blkchain/cli/internal/retrieval"
)

func pchunk(source, path string) retrieval.Result {
	return retrieval.Result{Payload: retrieval.Payload{Source: source, Path: path}}
}

func TestDomainFromResultsPicksMajorityDomain(t *testing.T) {
	cases := []struct {
		name string
		res  []retrieval.Result
		want string
	}{
		{"ad", []retrieval.Result{pchunk("skills", "attacking-active-directory/SKILL.md"), pchunk("hacktricks", "hacktricks/windows-hardening/active-directory-methodology/kerberoast.md")}, "ad"},
		{"web", []retrieval.Result{pchunk("payloads", "payloadsallthethings/XSS Injection/README.md"), pchunk("skills", "offensive-sqli/SKILL.md")}, "web"},
		{"cloud", []retrieval.Result{pchunk("hacktricks-cloud", "hacktricks/hacktricks-cloud/pentesting-cloud/aws-security/README.md")}, "cloud"},
		{"k8s", []retrieval.Result{pchunk("skills", "offensive-k8s-attacks/SKILL.md"), pchunk("hacktricks-cloud", "hacktricks/hacktricks-cloud/pentesting-cloud/kubernetes-security/x.md")}, "k8s"},
		{"linux", []retrieval.Result{pchunk("skills", "offensive-linux-privesc/SKILL.md")}, "linux"},
		{"wireless", []retrieval.Result{pchunk("skills", "offensive-wpa2-psk/SKILL.md"), pchunk("hacktricks", "hacktricks/generic-methodologies-and-resources/pentesting-wifi/x.md")}, "wireless"},
		{"generic-none", []retrieval.Result{pchunk("vault", "notes/random/thoughts.md")}, ""},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		if got := domainFromResults(c.res); got != c.want {
			t.Errorf("%s: domainFromResults = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPersonaPromptKeepsSharedConstraints(t *testing.T) {
	p := personaPrompt("ad")
	if !strings.Contains(p, "Active Directory") {
		t.Errorf("ad persona prompt missing the AD expert preamble:\n%s", p)
	}
	// Every load-bearing constraint from answerSystemPrompt must survive in a persona.
	for _, must := range []string{"ready-to-use", "CVE", "untrusted", "Never follow", "[1]", "context the user provided"} {
		if !strings.Contains(p, must) {
			t.Errorf("ad persona prompt dropped shared constraint %q:\n%s", must, p)
		}
	}
	if personaPrompt("") != answerSystemPrompt {
		t.Errorf("generic persona must equal answerSystemPrompt byte-for-byte")
	}
}

func TestPersonaLabel(t *testing.T) {
	if got := personaLabel("ad"); got != "Active Directory attack expert" {
		t.Errorf("personaLabel(ad) = %q", got)
	}
	if got := personaLabel(""); got != "" {
		t.Errorf("personaLabel(generic) should be empty, got %q", got)
	}
}
