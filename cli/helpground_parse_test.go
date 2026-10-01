package main

import "testing"

func hasTok(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestParseToolHelpFlags(t *testing.T) {
	help := `Usage: nmap [options] {target}
  -sV: Probe open ports to determine service/version info
  -p <port ranges>: Only scan specified ports
  --script=<Lua scripts>: run scripts
  --min-rate <number>`
	got := parseToolHelp(help)
	for _, f := range []string{"-sV", "-p", "--script", "--min-rate"} {
		if !hasTok(got.Flags, f) {
			t.Fatalf("expected flag %q in %#v", f, got.Flags)
		}
	}
}

func TestParseToolHelpSubcommands(t *testing.T) {
	help := `usage: git [--version] <command> [<args>]

These are common Git commands:

Commands:
   clone     Clone a repository
   push      Update remote refs
   commit    Record changes

See 'git help <command>'.`
	got := parseToolHelp(help)
	for _, c := range []string{"clone", "push", "commit"} {
		if !hasTok(got.Subcommands, c) {
			t.Fatalf("expected subcommand %q in %#v", c, got.Subcommands)
		}
	}
}

func TestParseToolHelpSlashGroupedFlags(t *testing.T) {
	got := parseToolHelp("  -oN/-oX/-oS/-oG <file>: Output scan in the given format\n")
	for _, f := range []string{"-oN", "-oX", "-oS", "-oG"} {
		if !hasTok(got.Flags, f) {
			t.Fatalf("expected slash-grouped flag %q in %#v", f, got.Flags)
		}
	}
}

func TestParseToolHelpEmpty(t *testing.T) {
	got := parseToolHelp("   \n  ")
	if len(got.Flags) != 0 || len(got.Subcommands) != 0 {
		t.Fatalf("empty help must yield empty interface: %#v", got)
	}
}

func TestParseToolHelpNoSubcommandSection(t *testing.T) {
	got := parseToolHelp("Usage: tool [-a] [-b]\n  -a do a\n  -b do b\n")
	if len(got.Subcommands) != 0 {
		t.Fatalf("no commands section must yield no subcommands: %#v", got.Subcommands)
	}
}
