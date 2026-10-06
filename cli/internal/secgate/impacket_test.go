package secgate

import (
	"slices"
	"strings"
	"testing"
)

// TestImpacketTargetGrammar is the two-sided audit of the credential operand.
// The host must reach the scope check, the credential must not be mistaken for
// one, and an operand with no usable host must fail closed.
func TestImpacketTargetGrammar(t *testing.T) {
	cases := []struct {
		args []string
		want []string
		ok   bool
	}{
		// The host after the last '@', with the domain and password ignored.
		{[]string{"CORP/svc:Passw0rd@192.0.2.10"}, []string{"192.0.2.10"}, true},
		{[]string{"CORP/svc@dc01.corp.local"}, []string{"dc01.corp.local"}, true},
		{[]string{"svc@192.0.2.10"}, []string{"192.0.2.10"}, true},
		// A password containing an @ must not shift the host.
		{[]string{"CORP/svc:p@ss@192.0.2.10"}, []string{"192.0.2.10"}, true},
		// A -hashes LM:NT pair parses as host:port to the generic reader; here it
		// must not become a target.
		{
			[]string{"-hashes", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "CORP/svc@192.0.2.10"},
			[]string{"192.0.2.10"}, true,
		},
		// An output filename parses as a hostname; it must not become a target.
		{[]string{"-outputfile", "report.txt", "CORP/svc@192.0.2.10"}, []string{"192.0.2.10"}, true},
		// Host flags, spaced and glued.
		{[]string{"-dc-ip", "192.0.2.5", "CORP/svc@192.0.2.10"}, []string{"192.0.2.5", "192.0.2.10"}, true},
		{[]string{"-target-ip=192.0.2.6", "CORP/svc@dc01.corp.local"}, []string{"192.0.2.6", "dc01.corp.local"}, true},
		{[]string{"-t", "smb://192.0.2.10"}, []string{"192.0.2.10"}, true},
		// A port suffix is dropped.
		{[]string{"CORP/svc@192.0.2.10:445"}, []string{"192.0.2.10"}, true},
		// A command operand for psexec is not a target.
		{[]string{"CORP/svc:p@192.0.2.10", "whoami"}, []string{"192.0.2.10"}, true},
		// Fail closed: an operand whose host half is not a host.
		{[]string{"CORP/svc:p@"}, nil, false},
		{[]string{"CORP/svc:p@not a host"}, nil, false},
		{[]string{"-dc-ip", "999.999.999.999", "CORP/svc@192.0.2.10"}, []string{"192.0.2.10"}, false},
	}
	for _, c := range cases {
		got, ok := ExtractTargets(Command{Binary: "secretsdump.py", Args: c.args})
		if ok != c.ok {
			t.Errorf("ExtractTargets(%v) ok = %t, want %t (targets %v)", c.args, ok, c.ok, got)
			continue
		}
		if c.ok && !slices.Equal(got, c.want) {
			t.Errorf("ExtractTargets(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// TestImpacketTargetsAreScopeChecked proves the extracted host actually reaches
// the scope decision, rather than the grammar being exercised in isolation.
func TestImpacketTargetsAreScopeChecked(t *testing.T) {
	s, err := ParseScope(strings.NewReader("192.0.2.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	in, ok := ExtractTargets(Command{Binary: "psexec.py", Args: []string{"CORP/svc:p@192.0.2.10", "whoami"}})
	if !ok || len(in) != 1 || !s.InScope(in[0]) {
		t.Fatalf("in-scope impacket target not accepted: %v %t", in, ok)
	}
	out, ok := ExtractTargets(Command{Binary: "psexec.py", Args: []string{"CORP/svc:p@198.51.100.9", "whoami"}})
	if !ok || len(out) != 1 {
		t.Fatalf("out-of-scope impacket target not extracted: %v %t", out, ok)
	}
	if s.InScope(out[0]) {
		t.Fatalf("out-of-scope impacket target %q accepted", out[0])
	}
}

// TestNtlmrelayxMustNameOneTarget closes the relay's scope hole: with no -t it
// relays to whatever authenticates to it, and -tf reads targets from a file.
func TestNtlmrelayxMustNameOneTarget(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-smb2support"},
		{"-tf", "targets.txt"},
		{"--target-file", "targets.txt"},
		{"-t", "smb://192.0.2.10", "-tf", "targets.txt"},
	} {
		denied(t, "ntlmrelayx.py "+join(args), Classify(Command{Binary: "ntlmrelayx.py", Args: args}))
	}
	allowed(t, "ntlmrelayx.py -t", Classify(Command{
		Binary: "ntlmrelayx.py", Args: []string{"-t", "smb://192.0.2.10", "-smb2support"}}))
	// The requirement applies to the relay only, not to every entry point.
	allowed(t, "secretsdump.py", Classify(Command{
		Binary: "secretsdump.py", Args: []string{"CORP/svc:p@192.0.2.10"}}))
}

// TestImpacketOutputFileIsConfined keeps results inside the scratch directory.
func TestImpacketOutputFileIsConfined(t *testing.T) {
	if _, bad := FileAccessViolation(Command{Binary: "secretsdump.py",
		Args: []string{"-outputfile", "/etc/dump", "CORP/svc:p@192.0.2.10"}}); !bad {
		t.Error("secretsdump.py -outputfile outside the scratch directory should be refused")
	}
	if arg, bad := FileAccessViolation(Command{Binary: "secretsdump.py",
		Args: []string{"-outputfile", "dump", "CORP/svc:p@192.0.2.10"}}); bad {
		t.Errorf("secretsdump.py -outputfile in the scratch directory should pass, refused %q", arg)
	}
}

// TestImpacketCredentialsStayInTheRecord pins the deliberate decision that the
// credential is not redacted: these tools take it on the command line, and the
// transcript is expected to show exactly what ran.
func TestImpacketCredentialsStayInTheRecord(t *testing.T) {
	c := Command{Binary: "secretsdump.py", Args: []string{"CORP/svc:Passw0rd@192.0.2.10"}}
	if !strings.Contains(Signature(c), "Passw0rd") {
		t.Error("the recorded signature should carry the credential verbatim")
	}
}
