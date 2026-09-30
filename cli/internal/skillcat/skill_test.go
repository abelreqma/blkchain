package skillcat

import (
	"strings"
	"testing"
)

const sampleSkill = `---
name: abusing-adcs
description: "AD CS abuse - ESC1-ESC16, vulnerable templates."
verified: 2026-07-27
---

# Abusing AD CS

## When to Use
When a domain has a CA.
`

func TestParseSkill(t *testing.T) {
	s, err := ParseSkill("/x/abusing-adcs/SKILL.md", []byte(sampleSkill))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "abusing-adcs" {
		t.Errorf("name = %q", s.Name)
	}
	if !strings.Contains(s.Description, "AD CS abuse") {
		t.Errorf("description = %q", s.Description)
	}
	if s.Verified != "2026-07-27" {
		t.Errorf("verified = %q", s.Verified)
	}
	if !strings.Contains(s.Body, "# Abusing AD CS") {
		t.Errorf("body missing heading: %q", s.Body)
	}
	if len(s.Digest) != 64 {
		t.Errorf("digest not a hex sha256: %q", s.Digest)
	}
}

func TestParseSkillDigestStable(t *testing.T) {
	a, _ := ParseSkill("/x/SKILL.md", []byte(sampleSkill))
	b, _ := ParseSkill("/x/SKILL.md", []byte(sampleSkill))
	if a.Digest != b.Digest {
		t.Error("digest not stable for identical input")
	}
	c, _ := ParseSkill("/x/SKILL.md", []byte(sampleSkill+"\nextra\n"))
	if c.Digest == a.Digest {
		t.Error("digest did not change for changed input")
	}
}

func TestParseSkillRejectsMissingFields(t *testing.T) {
	cases := []string{
		"no frontmatter at all\n",
		"---\ndescription: x\n---\nbody\n",       // missing name
		"---\nname: x\n---\nbody\n",              // missing description
		"---\nname: \"\"\ndescription: y\n---\n", // empty name
	}
	for i, c := range cases {
		if _, err := ParseSkill("/x/SKILL.md", []byte(c)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
