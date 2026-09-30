package secgate

import (
	"strings"
	"testing"
)

func TestClassifyDeniesMetacharacters(t *testing.T) {
	bad := [][]string{
		{"sh", "-c", "rm -rf /"},         // denied by the shell rule
		{"curl", "http://x; rm -rf /"},   // ';'
		{"nmap", "10.0.0.1", "|", "tee"}, // '|'
		{"x", "$(whoami)"},               // command substitution
		{"x", "a && b"},                  // chaining
		{"x", "`id`"},                    // backtick
		{"x", "out > /etc/passwd"},       // redirection
		{"x", "line1\nline2"},            // newline injection
	}
	for _, args := range bad {
		d := Classify(Command{Binary: args[0], Args: args[1:]})
		if d.Allowed {
			t.Errorf("Classify(%v) allowed a metacharacter command", args)
		}
	}
}

func TestClassifyDeniesEmptyBinary(t *testing.T) {
	if Classify(Command{Binary: "", Args: []string{"x"}}).Allowed {
		t.Error("empty binary must be denied")
	}
}

func TestClassifyAllowsCleanBoundedCommand(t *testing.T) {
	d := Classify(Command{Binary: "nmap", Args: []string{"-p", "80,443", "10.0.0.5"}})
	if !d.Allowed {
		t.Errorf("a clean bounded nmap should pass the classifier: %q", d.Reason)
	}
	d2 := Classify(Command{Binary: "curl", Args: []string{"https://host.example.com/x"}})
	if !d2.Allowed {
		t.Errorf("a clean curl should pass the classifier: %q", d2.Reason)
	}
}

func TestClassifyDeniesUnboundedNmapWithSuggestion(t *testing.T) {
	d := Classify(Command{Binary: "nmap", Args: []string{"10.0.0.0/8"}})
	if d.Allowed {
		t.Error("nmap with no port bound over a /8 should be denied as unbounded")
	}
	if !strings.Contains(strings.ToLower(d.Suggestion+d.Reason), "-p") && !strings.Contains(strings.ToLower(d.Suggestion+d.Reason), "top-ports") {
		t.Errorf("denied unbounded nmap should suggest a bounded form, got reason=%q suggestion=%q", d.Reason, d.Suggestion)
	}
}

func TestClassifyDeniesUnboundedCracker(t *testing.T) {
	if Classify(Command{Binary: "hashcat", Args: []string{"-m", "0", "hashes.txt", "wordlist.txt"}}).Allowed {
		// no --runtime / bounded keyspace
		t.Error("hashcat without a runtime/keyspace bound should be denied")
	}
}

func TestClassifyDeniesEveryMetacharacterInArgAndBinary(t *testing.T) {
	for _, tok := range metaTokens {
		if d := Classify(Command{Binary: "curl", Args: []string{"a" + tok + "b"}}); d.Allowed {
			t.Errorf("arg containing %q was allowed", tok)
		}
		if d := Classify(Command{Binary: "cu" + tok + "rl", Args: []string{"x"}}); d.Allowed {
			t.Errorf("binary containing %q was allowed", tok)
		}
	}
	for _, s := range []string{"\r", "\x00", "$(id)", "a&&b", "a||b", ">>out", "a`b"} {
		if Classify(Command{Binary: "x", Args: []string{s}}).Allowed {
			t.Errorf("arg %q was allowed", s)
		}
	}
}

func TestClassifyDeniesShellInterpreters(t *testing.T) {
	for _, bin := range []string{"sh", "/bin/bash", "ZSH", "dash"} {
		if Classify(Command{Binary: bin, Args: []string{"-lc", "id"}}).Allowed {
			t.Errorf("shell %q was allowed", bin)
		}
	}
}

func TestClassifyDeniesWhitespaceBinaryAndBoundedCrackerAllowed(t *testing.T) {
	if Classify(Command{Binary: "  \t"}).Allowed {
		t.Error("whitespace-only binary must be denied")
	}
	if !Classify(Command{Binary: "/usr/bin/hashcat", Args: []string{"--runtime=300", "-m", "0", "h", "w"}}).Allowed {
		t.Error("hashcat with --runtime=300 should pass")
	}
	if Classify(Command{Binary: "/usr/bin/NMAP", Args: []string{"10.0.0.1"}}).Allowed {
		t.Error("path/case variants of nmap must still be treated as unbounded")
	}
	if !Classify(Command{Binary: "unknowntool", Args: []string{"x"}}).Allowed {
		t.Error("unknown clean binary is left to the allowlist")
	}
}

func TestClassifyDeniesWrappersAndExtraShells(t *testing.T) {
	cases := []Command{
		{Binary: "env", Args: []string{"sh", "-c", "id"}},
		{Binary: "sudo", Args: []string{"nmap", "-p", "80", "10.0.0.5"}},
		{Binary: " sh"},
		{Binary: "sh "},
		{Binary: "\tbash\t"},
		{Binary: "busybox", Args: []string{"sh"}},
		{Binary: "/usr/bin/xargs"},
		{Binary: "PowerShell"},
		{Binary: "pwsh"}, {Binary: "cmd"}, {Binary: "nu"}, {Binary: "xonsh"},
		{Binary: "ash"}, {Binary: "rbash"}, {Binary: "mksh"}, {Binary: "yash"},
		{Binary: "su"}, {Binary: "doas"}, {Binary: "nohup"}, {Binary: "nice"},
		{Binary: "timeout"}, {Binary: "setsid"}, {Binary: "stdbuf"}, {Binary: "watch"},
		{Binary: "script"}, {Binary: "chroot"}, {Binary: "command"}, {Binary: "exec"},
	}
	for _, c := range cases {
		d := Classify(c)
		if d.Allowed {
			t.Errorf("Classify(%q %v) allowed a shell/wrapper", c.Binary, c.Args)
		} else if !strings.Contains(d.Reason, "not permitted directly") {
			t.Errorf("Classify(%q) reason = %q", c.Binary, d.Reason)
		}
	}
}

func TestClassifyDeniesInlineInterpreters(t *testing.T) {
	cases := []Command{
		{Binary: "python", Args: []string{"-c", "import os"}},
		{Binary: "python3", Args: []string{"-c", "import os"}},
		{Binary: "perl", Args: []string{"-e", "system('id')"}},
		{Binary: "node", Args: []string{"-e", "1"}},
		{Binary: "find", Args: []string{".", "-exec", "id", "{}", "+"}},
		{Binary: "awk", Args: []string{`BEGIN{system("id")}`}},
		{Binary: "python2"}, {Binary: "ruby"}, {Binary: "nodejs"}, {Binary: "php"},
		{Binary: "lua"}, {Binary: "gawk"}, {Binary: "/usr/bin/python3"},
	}
	for _, c := range cases {
		if d := Classify(c); d.Allowed {
			t.Errorf("Classify(%q %v) allowed an inline interpreter", c.Binary, c.Args)
		}
	}
}

func TestClassifyCrackerBoundsAreSplit(t *testing.T) {
	if _, tripped := classifyUnbounded(Command{Binary: "john", Args: []string{"--max-run-time", "300", "hashes.txt"}}); tripped {
		t.Error("bounded john must not be denied by classifyUnbounded")
	}
	if _, tripped := classifyUnbounded(Command{Binary: "john", Args: []string{"--max-candidates=1000", "h"}}); tripped {
		t.Error("john --max-candidates=N must not be denied by classifyUnbounded")
	}
	if _, tripped := classifyUnbounded(Command{Binary: "hashcat", Args: []string{"--runtime", "300", "-m", "0", "h", "w"}}); tripped {
		t.Error("bounded hashcat must not be denied by classifyUnbounded")
	}
	d, tripped := classifyUnbounded(Command{Binary: "john", Args: []string{"hashes.txt"}})
	if !tripped || d.Allowed {
		t.Fatal("unbounded john must be denied")
	}
	if strings.Contains(d.Suggestion, "--runtime") || !strings.Contains(d.Suggestion, "--max-run-time") {
		t.Errorf("john suggestion must name john's flag, got %q", d.Suggestion)
	}
	if _, tripped := classifyUnbounded(Command{Binary: "john", Args: []string{"--runtime", "300"}}); !tripped {
		t.Error("hashcat's --runtime must not bound john")
	}
	d, _ = classifyUnbounded(Command{Binary: "hashcat", Args: []string{"h"}})
	if !strings.Contains(d.Suggestion, "--runtime") {
		t.Errorf("hashcat suggestion = %q", d.Suggestion)
	}
}
