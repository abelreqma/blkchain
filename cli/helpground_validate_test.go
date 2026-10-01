package main

import "testing"

func TestExtractProposedOptions(t *testing.T) {
	p := extractProposedOptions([]string{"-sV", "--script=http", "-p", "80", "10.0.0.5"})
	if len(p.Flags) != 3 || p.Flags[0] != "-sV" || p.Flags[1] != "--script" || p.Flags[2] != "-p" {
		t.Fatalf("flags: %#v", p.Flags)
	}
	// The first token is a flag, so there is no subcommand candidate: "80" is a
	// value/operand, not a subcommand, and must not be mistaken for one.
	if p.Subcommand != "" {
		t.Fatalf("subcommand candidate should be empty when args lead with a flag: %q", p.Subcommand)
	}
}

func TestExtractProposedOptionsLeadingSubcommand(t *testing.T) {
	p := extractProposedOptions([]string{"run", "--rm", "img"})
	if p.Subcommand != "run" {
		t.Fatalf("a leading non-flag token is the subcommand: %q", p.Subcommand)
	}
	if len(p.Flags) != 1 || p.Flags[0] != "--rm" {
		t.Fatalf("flags: %#v", p.Flags)
	}
}

func TestExtractProposedOptionsValueFlagNotSubcommand(t *testing.T) {
	// A value following a flag (docker -H host run) must not be read as a
	// subcommand: the first token is a flag, so there is no subcommand candidate.
	p := extractProposedOptions([]string{"-H", "host", "run"})
	if p.Subcommand != "" {
		t.Fatalf("value after a leading flag must not be a subcommand: %q", p.Subcommand)
	}
}

func TestExtractProposedOptionsDashDashStops(t *testing.T) {
	p := extractProposedOptions([]string{"-a", "--", "-notaflag"})
	if len(p.Flags) != 1 || p.Flags[0] != "-a" {
		t.Fatalf("tokens after -- are positionals: %#v", p.Flags)
	}
}

func TestFlagKnownPermissive(t *testing.T) {
	flags := []string{"-s", "-S", "-V", "-p", "--script"}
	cases := []struct {
		tok  string
		want bool
	}{
		{"-sV", true},
		{"-p80", true},
		{"--script", true},
		{"--scrpt", false},
		{"-z", false},
		{"-sz", false},
	}
	for _, c := range cases {
		if got := flagKnown(c.tok, flags); got != c.want {
			t.Fatalf("flagKnown(%q) = %v, want %v", c.tok, got, c.want)
		}
	}
}

func TestValidateAgainstInterface(t *testing.T) {
	iface := toolInterface{Flags: []string{"-sV", "-p"}}
	uf, us := validateAgainstInterface(proposedOptions{Flags: []string{"-sV", "-X"}, Subcommand: "10.0.0.5"}, iface)
	if len(uf) != 1 || uf[0] != "-X" || us != "" {
		t.Fatalf("unknownFlags=%#v unknownSub=%q (positional must not be a subcommand when none listed)", uf, us)
	}

	gitIface := toolInterface{Subcommands: []string{"clone", "push"}}
	uf2, us2 := validateAgainstInterface(proposedOptions{Subcommand: "foobar"}, gitIface)
	if len(uf2) != 0 || us2 != "foobar" {
		t.Fatalf("unknown subcommand should be flagged: uf=%#v us=%q", uf2, us2)
	}
	_, us3 := validateAgainstInterface(proposedOptions{Subcommand: "clone"}, gitIface)
	if us3 != "" {
		t.Fatalf("known subcommand must pass: %q", us3)
	}
}
