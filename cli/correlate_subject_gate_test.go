package main

import (
	"testing"

	"blkchain/cli/internal/retrieval"
)

// correlate_subject_gate_test.go covers the specificity gate that grounds a
// discovered service's product. A cited, product-adjacent page is a lead and not
// evidence that the service is vulnerable, so the product path requires the hit to
// be ABOUT the product - named in its locating metadata - rather than merely to
// mention it in a body somewhere.

func meta(source, path, section, text string) retrieval.Payload {
	return retrieval.Payload{Source: source, Path: path, Section: section, Text: text}
}

// A body-only mention no longer grounds a product. Measured on the live corpus,
// this is what let a generic vulnerability-classes page ground "Apache httpd" and
// an open-redirect page ground "Grafana".
func TestSubjectGateRejectsBodyOnlyMention(t *testing.T) {
	p := meta("skills", "offensive-vuln-classes/SKILL.md", "Vulnerability Classes",
		"Day 3 covers integer overflows in Apache httpd and other servers.")
	if citationNamesSubject(p, "apache httpd") {
		t.Error("a generic page mentioning the product in its body must not ground it")
	}
	// The same payload still satisfies the concept-token gate, which the OWASP and
	// logic-gap detectors rely on, so narrowing the product path left them alone.
	if !citationMentions(p, "apache httpd") {
		t.Error("citationMentions must still match body text for the concept-token callers")
	}
}

// A page that is about the product names it in path or section.
func TestSubjectGateAcceptsProductInLocatingMetadata(t *testing.T) {
	for _, tc := range []struct {
		term string
		p    retrieval.Payload
	}{
		{"elasticsearch", meta("hacktricks", "network-services-pentesting/9200-pentesting-elasticsearch.md", "9200 - Elasticsearch", "body")},
		{"jenkins", meta("hacktricks", "pentesting-ci-cd/jenkins-security/README.md", "Jenkins", "body")},
		{"zabbix", meta("hacktricks", "pentesting-web/zabbix.md", "Zabbix", "body")},
		{"gitlab", meta("hacktricks", "pentesting-web/gitlab.md", "GitLab Enumeration", "body")},
	} {
		if !citationNamesSubject(tc.p, tc.term) {
			t.Errorf("%q must ground on %s", tc.term, tc.p.Path)
		}
	}
}

// Every token of a multi-word product must be present, so a sibling in the same
// vendor namespace does not ground.
func TestSubjectGateRequiresEveryProductToken(t *testing.T) {
	tomcat := meta("hacktricks", "pentesting-web/tomcat.md", "Apache Tomcat", "body")
	if citationNamesSubject(tomcat, "apache httpd") {
		t.Error("an Apache Tomcat page must not ground Apache httpd")
	}
	if !citationNamesSubject(tomcat, "apache tomcat") {
		t.Error("an Apache Tomcat page must ground Apache Tomcat")
	}
}

// A product whose corpus page is named for the protocol it serves grounds through
// its measured alias. Without these, OpenSSH and Samba lost grounding entirely.
func TestSubjectGateAcceptsMeasuredProtocolAlias(t *testing.T) {
	ssh := meta("hacktricks", "network-services-pentesting/pentesting-ssh.md",
		"22 - Pentesting SSH/SFTP > Recent Critical Vulnerabilities (2024)", "body")
	if !citationNamesSubject(ssh, "openssh") {
		t.Error("OpenSSH must ground on the SSH service page through its alias")
	}
	smb := meta("hacktricks", "network-services-pentesting/pentesting-smb/README.md",
		"139,445 - Pentesting SMB", "body")
	if !citationNamesSubject(smb, "samba") {
		t.Error("Samba must ground on the SMB service page through its alias")
	}
}

// An alias applies only to the product it was measured for, so it cannot ground an
// unrelated product that happens to speak the same protocol.
func TestProtocolAliasIsScopedToItsProduct(t *testing.T) {
	ssh := meta("hacktricks", "network-services-pentesting/pentesting-ssh.md", "22 - Pentesting SSH/SFTP", "body")
	for _, other := range []string{"dropbear", "tectia ssh server", "redis"} {
		if citationNamesSubject(ssh, other) {
			t.Errorf("the SSH page must not ground %q, which has no alias entry", other)
		}
	}
}

// No alias is a vendor-only token. Measured on the live corpus, "apache" as an
// alias for Apache httpd first matched an Apache STRUTS CVE page, a different
// product, so Apache httpd has no alias and falls to the strict rule.
func TestNoAliasIsAVendorOnlyToken(t *testing.T) {
	if _, ok := subjectAliases["apache httpd"]; ok {
		t.Fatal("Apache httpd must have no alias; the vendor token grounds a sibling product")
	}
	struts := meta("payloads", "payloadsallthethings/CVE Exploits/README.md",
		"Big CVEs in the last 15 years > CVE-2017-5638 - Apache Struts", "body")
	if citationNamesSubject(struts, "apache httpd") {
		t.Error("an Apache Struts CVE page must not ground Apache httpd")
	}
	for product, aliases := range subjectAliases {
		for _, alias := range aliases {
			if alias == "" {
				t.Errorf("%s has an empty alias", product)
			}
		}
	}
}

// A fabricated product grounds nothing, whatever the retrieved page says.
func TestSubjectGateRejectsAFabricatedProduct(t *testing.T) {
	for _, p := range []retrieval.Payload{
		meta("skills", "offensive-vuln-classes/SKILL.md", "Vulnerability Classes", "generic notes"),
		meta("hacktricks", "network-services-pentesting/pentesting-ssh.md", "22 - Pentesting SSH", "generic notes"),
	} {
		if citationNamesSubject(p, "blargonaut widget broker") {
			t.Errorf("a fabricated product must not ground on %s", p.Path)
		}
	}
}

// An empty term carries no specificity requirement at the gate itself; the callers
// that pass one skip the gate entirely, which is the deterministic logic-gap path.
func TestSubjectGateWithEmptyTermGroundsNothing(t *testing.T) {
	if citationNamesSubject(meta("s", "p.md", "sec", "text"), "") {
		t.Error("an empty term must not satisfy the subject gate")
	}
}
