package secgate

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

var smbDeniedSpellings = []struct {
	name string
	args []string
}{
	// -c / --command (command channel)
	{"smbclient", []string{"//10.0.0.5/share", "-N", "-c", "ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "-cls"}},
	{"smbclient", []string{"//10.0.0.5/share", "-c=ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "-Nc", "ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "-Ncls"}},
	{"smbclient", []string{"//10.0.0.5/share", "-gEc", "ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "--command", "ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "--command=ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "--comm=ls"}},
	{"smbclient", []string{"//10.0.0.5/share", "--c", "ls"}},
	{"/usr/bin/smbclient", []string{"//10.0.0.5/share", "-c", "ls"}},
	{"rpcclient", []string{"-N", "10.0.0.5", "-c", "srvinfo"}},
	{"rpcclient", []string{"-N", "10.0.0.5", "-csrvinfo"}},
	{"rpcclient", []string{"-Nc", "srvinfo", "10.0.0.5"}},
	{"rpcclient", []string{"10.0.0.5", "--command=srvinfo"}},
	{"rpcclient", []string{"10.0.0.5", "--command", "srvinfo"}},
	{"rpcclient", []string{"10.0.0.5", "--comm", "srvinfo"}},
	// -T / --tar (positional local tar file)
	{"smbclient", []string{"//10.0.0.5/share", "-Tc", "out"}},
	{"smbclient", []string{"//10.0.0.5/share", "-T", "x", "in"}},
	{"smbclient", []string{"//10.0.0.5/share", "-NTx", "in"}},
	{"smbclient", []string{"//10.0.0.5/share", "--tar=c", "out"}},
	{"smbclient", []string{"//10.0.0.5/share", "--tar", "c", "out"}},
	{"smbclient", []string{"//10.0.0.5/share", "--ta=c", "out"}},
	// -A / --authentication-file (credential file)
	{"smbclient", []string{"//10.0.0.5/share", "-A", "creds"}},
	{"smbclient", []string{"//10.0.0.5/share", "-Acreds"}},
	{"smbclient", []string{"//10.0.0.5/share", "-NA", "creds"}},
	{"smbclient", []string{"//10.0.0.5/share", "--authentication-file=creds"}},
	{"smbclient", []string{"//10.0.0.5/share", "--authentication-file", "creds"}},
	{"smbclient", []string{"//10.0.0.5/share", "--auth=creds"}},
	{"rpcclient", []string{"10.0.0.5", "-A", "creds"}},
	{"rpcclient", []string{"10.0.0.5", "-Acreds"}},
	{"rpcclient", []string{"10.0.0.5", "-NA", "creds"}},
	{"rpcclient", []string{"10.0.0.5", "--authentication-file=creds"}},
	{"rpcclient", []string{"10.0.0.5", "--authentication-file", "creds"}},
	// -s / --configfile / --option (config indirection)
	{"smbclient", []string{"//10.0.0.5/share", "-s", "smb.conf"}},
	{"smbclient", []string{"//10.0.0.5/share", "-ssmb.conf"}},
	{"smbclient", []string{"//10.0.0.5/share", "-Ns", "smb.conf"}},
	{"smbclient", []string{"//10.0.0.5/share", "--configfile=smb.conf"}},
	{"smbclient", []string{"//10.0.0.5/share", "--configfile", "smb.conf"}},
	{"smbclient", []string{"//10.0.0.5/share", "--conf=smb.conf"}},
	{"smbclient", []string{"//10.0.0.5/share", "--option=include=x"}},
	{"smbclient", []string{"//10.0.0.5/share", "--option", "include=x"}},
	{"smbclient", []string{"//10.0.0.5/share", "--opt=include=x"}},
	{"rpcclient", []string{"10.0.0.5", "-s", "smb.conf"}},
	{"rpcclient", []string{"10.0.0.5", "-ssmb.conf"}},
	{"rpcclient", []string{"10.0.0.5", "--configfile=smb.conf"}},
	{"rpcclient", []string{"10.0.0.5", "--option=include=x"}},
	// kerberos ccache file and machine secret
	{"smbclient", []string{"//10.0.0.5/share", "--use-krb5-ccache=x"}},
	{"smbclient", []string{"//10.0.0.5/share", "--use-krb5-ccache", "x"}},
	{"smbclient", []string{"//10.0.0.5/share", "-P"}},
	{"smbclient", []string{"//10.0.0.5/share", "-NP"}},
	{"smbclient", []string{"//10.0.0.5/share", "--machine-pass"}},
	{"rpcclient", []string{"10.0.0.5", "--use-krb5-ccache=x"}},
	{"rpcclient", []string{"10.0.0.5", "-P"}},
	{"rpcclient", []string{"10.0.0.5", "--machine-pass"}},
	// nbtscan -f (targets from a file)
	{"nbtscan", []string{"-f", "hosts"}},
	{"nbtscan", []string{"-fhosts"}},
	{"nbtscan", []string{"-vf", "hosts"}},
	{"nbtscan", []string{"-f", "-"}},
	{"nbtscan", []string{"--file=hosts"}},
}

func TestSMBEnumDeniedFlagsEverySpelling(t *testing.T) {
	for _, tc := range smbDeniedSpellings {
		d := Classify(Command{Binary: tc.name, Args: tc.args})
		if d.Allowed {
			t.Errorf("Classify(%q %v) allowed a denied flag", tc.name, tc.args)
		}
	}
}

func TestSMBEnumBenignInvocationsAllowed(t *testing.T) {
	benign := []Command{
		{Binary: "smbclient", Args: []string{"-L", "10.0.0.5", "-N"}},
		{Binary: "smbclient", Args: []string{"-NL", "10.0.0.5"}},
		{Binary: "smbclient", Args: []string{"-L", "//10.0.0.5", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-U", "guest%"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-Ucarl%pw"}},
		{Binary: "smbclient", Args: []string{"-I", "10.0.0.5", "//corp.example/share", "-N"}},
		{Binary: "smbclient", Args: []string{"--ip-address=10.0.0.5", "-L", "corp.example", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-p", "445", "-m", "SMB3", "-d", "1", "-g"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-N", "-l", "logs"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "--no-pass", "--log-basename=logs"}},
		{Binary: "rpcclient", Args: []string{"-N", "10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"-U", "guest%", "-I", "10.0.0.5", "corp.example"}},
		{Binary: "rpcclient", Args: []string{"-N", "-l", "logs", "10.0.0.5"}},
		{Binary: "nbtscan", Args: []string{"10.0.0.5"}},
		{Binary: "nbtscan", Args: []string{"-v", "-t", "500", "10.0.0.5"}},
		{Binary: "nbtscan", Args: []string{"-r", "-q", "10.0.0.5"}},
		{Binary: "nbtscan", Args: []string{"-O", "out", "10.0.0.5"}},
		{Binary: "showmount", Args: []string{"10.0.0.5"}},
		{Binary: "showmount", Args: []string{"-e", "10.0.0.5"}},
		{Binary: "showmount", Args: []string{"-a", "corp.example"}},
		{Binary: "showmount", Args: []string{"--exports", "--no-headers", "10.0.0.5"}},
	}
	for _, c := range benign {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied a benign command: %q", c.Binary, c.Args, d.Reason)
		}
		if arg, bad := FileAccessViolation(c); bad {
			t.Errorf("FileAccessViolation(%q %v) denied a benign command (%q)", c.Binary, c.Args, arg)
		}
	}
}

func TestSMBEnumLogAndOutputPathsBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"smbclient", []string{"-l", "/tmp/x"}},
		{"smbclient", []string{"-l/tmp/x"}},
		{"smbclient", []string{"-l", "../x"}},
		{"smbclient", []string{"-Nl", "/x"}},
		{"smbclient", []string{"--log-basename=/x"}},
		{"smbclient", []string{"--log-basename", "../x"}},
		{"smbclient", []string{"--log=/x"}},
		{"rpcclient", []string{"-l", "/tmp/x"}},
		{"rpcclient", []string{"-l../x"}},
		{"rpcclient", []string{"--log-basename=/x"}},
		{"nbtscan", []string{"-O", "/tmp/x", "10.0.0.5"}},
		{"nbtscan", []string{"-O../x", "10.0.0.5"}},
		{"nbtscan", []string{"-vO", "/x", "10.0.0.5"}},
	} {
		if arg, bad := FileAccessViolation(Command{Binary: tc.name, Args: tc.args}); !bad {
			t.Errorf("FileAccessViolation(%q %v) allowed a path escape", tc.name, tc.args)
		} else if arg == "" {
			t.Errorf("FileAccessViolation(%q %v) must report the offending arg", tc.name, tc.args)
		}
	}
}

func newSMBGate(t *testing.T) *Gate {
	t.Helper()
	scope, err := ParseScope(strings.NewReader("10.0.0.0/24\ncorp.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("smbclient", "rpcclient", "nbtscan", "showmount")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// A glued or bundled host-flag value is invisible to ExtractTargets, so the
// classifier denies it before the scope check.
func TestSMBEnumGluedHostFlagDeniedByGate(t *testing.T) {
	g := newSMBGate(t)
	for _, c := range []Command{
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-Ievil.com", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-I8.8.8.8", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-NIevil.com"}},
		{Binary: "smbclient", Args: []string{"-Levil.com", "-N"}},
		{Binary: "smbclient", Args: []string{"-NL8.8.8.8"}},
		{Binary: "smbclient", Args: []string{"-Mevil.com"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-B8.8.8.255"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-I=evil.com"}},
		{Binary: "rpcclient", Args: []string{"-I8.8.8.8", "10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"-NIevil.com", "10.0.0.5"}},
	} {
		d := g.Authorize(context.Background(), c)
		if d.Allowed {
			t.Errorf("Authorize(%q %v) allowed a glued host flag", c.Binary, c.Args)
		} else if !strings.Contains(d.Reason, "glues or bundles") {
			t.Errorf("Authorize(%q %v) denied for the wrong reason: %q", c.Binary, c.Args, d.Reason)
		}
	}
}

func TestSMBEnumOutOfScopeTargetsDeniedByGate(t *testing.T) {
	g := newSMBGate(t)
	for _, c := range []Command{
		{Binary: "smbclient", Args: []string{"//evil.com/share", "-N"}},
		{Binary: "smbclient", Args: []string{"//8.8.8.8/share", "-N"}},
		{Binary: "smbclient", Args: []string{"//dc01/share", "-N"}},
		{Binary: "smbclient", Args: []string{"\\\\dc01\\share", "-N"}},
		{Binary: "smbclient", Args: []string{"\\\\evil.com\\share", "-N"}},
		{Binary: "smbclient", Args: []string{"\\\\8.8.8.8\\share", "-N"}},
		{Binary: "smbclient", Args: []string{"/\\evil.com/share", "-N"}},
		{Binary: "smbclient", Args: []string{"\\/evil.com\\share", "-N"}},
		{Binary: "smbclient", Args: []string{"-L", "//evil.com", "-N"}},
		{Binary: "smbclient", Args: []string{"-L", "evil.com", "-N"}},
		{Binary: "smbclient", Args: []string{"-M", "evil.com"}},
		{Binary: "smbclient", Args: []string{"-I", "8.8.8.8", "//10.0.0.5/share", "-N"}},
		{Binary: "smbclient", Args: []string{"--ip-address=8.8.8.8", "//10.0.0.5/share", "-N"}},
		{Binary: "smbclient", Args: []string{"--list=evil.com", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "//evil.com/share", "-N"}},
		{Binary: "smbclient", Args: []string{"smb://evil.com/share", "-N"}},
		{Binary: "rpcclient", Args: []string{"-N", "//evil.com"}},
		{Binary: "rpcclient", Args: []string{"-N", "\\\\8.8.8.8"}},
		{Binary: "rpcclient", Args: []string{"-N", "evil.com"}},
		{Binary: "rpcclient", Args: []string{"-N", "-I", "8.8.8.8", "10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"-N", "--ip-address=8.8.8.8", "10.0.0.5"}},
		{Binary: "nbtscan", Args: []string{"8.8.8.8"}},
		{Binary: "nbtscan", Args: []string{"10.0.0.0/24"}},
		{Binary: "nbtscan", Args: []string{"10.0.0.1-50"}},
		{Binary: "showmount", Args: []string{"-e", "8.8.8.8"}},
		{Binary: "showmount", Args: []string{"evil.com"}},
	} {
		d := g.Authorize(context.Background(), c)
		if d.Allowed {
			t.Errorf("Authorize(%q %v) allowed an out-of-scope or unverifiable target", c.Binary, c.Args)
		} else if !strings.Contains(d.Reason, "out of scope") && !strings.Contains(d.Reason, "unverifiable") {
			t.Errorf("Authorize(%q %v) denied for the wrong reason: %q", c.Binary, c.Args, d.Reason)
		}
	}
}

func TestSMBEnumGateAllowsBenignInScope(t *testing.T) {
	stubEnumFixtureResolver(t)
	g := newSMBGate(t)
	for _, c := range []Command{
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-N"}},
		{Binary: "smbclient", Args: []string{"\\\\10.0.0.5\\share", "-N"}},
		{Binary: "smbclient", Args: []string{"//corp.example/share", "-N"}},
		{Binary: "smbclient", Args: []string{"-L", "10.0.0.5", "-N"}},
		{Binary: "smbclient", Args: []string{"-NL", "10.0.0.5"}},
		{Binary: "smbclient", Args: []string{"-L", "//10.0.0.5", "-N"}},
		{Binary: "smbclient", Args: []string{"-I", "10.0.0.5", "//corp.example/share", "-N"}},
		{Binary: "smbclient", Args: []string{"--ip-address=10.0.0.5", "-L", "corp.example", "-N"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-Ucarl%pw", "-l", "logs"}},
		{Binary: "rpcclient", Args: []string{"-N", "10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"-N", "//10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"-U", "guest%", "-I", "10.0.0.5", "corp.example"}},
		{Binary: "nbtscan", Args: []string{"10.0.0.5"}},
		{Binary: "nbtscan", Args: []string{"-v", "-t", "500", "10.0.0.5"}},
		{Binary: "showmount", Args: []string{"-e", "10.0.0.5"}},
		{Binary: "showmount", Args: []string{"-a", "corp.example"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied a benign in-scope command: %q", c.Binary, c.Args, d.Reason)
		}
	}
}

func TestExtractTargetsUNCHost(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
		ok   bool
	}{
		{[]string{"//10.0.0.5/share"}, []string{"10.0.0.5"}, true},
		{[]string{"//Corp.Example/share/dir"}, []string{"corp.example"}, true},
		{[]string{"\\\\10.0.0.5\\share"}, []string{"10.0.0.5"}, true},
		{[]string{"/\\10.0.0.5/share"}, []string{"10.0.0.5"}, true},
		{[]string{"//10.0.0.5"}, []string{"10.0.0.5"}, true},
		{[]string{"\\\\corp.example"}, []string{"corp.example"}, true},
		{[]string{"//evil.com/a", "\\\\10.0.0.5\\b"}, []string{"evil.com", "10.0.0.5"}, true},
		{[]string{"//[::1]/share"}, []string{"::1"}, true},
		{[]string{"///evil.com/share"}, []string{"evil.com"}, true},
		{[]string{"////evil.com/share"}, []string{"evil.com"}, true},
		{[]string{"\\\\\\evil.com\\share"}, []string{"evil.com"}, true},
		{[]string{"/\\/evil.com"}, []string{"evil.com"}, true},
		{[]string{"///10.0.0.5/share"}, []string{"10.0.0.5"}, true},
		{[]string{"///"}, nil, false},
		{[]string{"//"}, nil, true},
		{[]string{"//dc01/share"}, []string{"dc01"}, true},
		{[]string{"\\\\dc01\\share"}, []string{"dc01"}, true},
		{[]string{"//bad_host!/share"}, nil, false},
		{[]string{"/etc/passwd"}, nil, true},
	} {
		got, ok := ExtractTargets(Command{Binary: "smbclient", Args: tc.args})
		if ok != tc.ok || strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("ExtractTargets(%q) = %v, %v; want %v, %v", tc.args, got, ok, tc.want, tc.ok)
		}
	}
}

// UNC extraction applies to smbclient and rpcclient only. For every other tool
// a //x or \\x token is a path or payload, not a target.
func TestUNCExtractionLimitedToSMBTools(t *testing.T) {
	for _, bin := range []string{"curl", "wget", "nc", "nmap", "ls"} {
		for _, a := range []string{"//etc/passwd", "\\\\windows\\win.ini", "//x", "///etc/passwd", "//evil.com/x"} {
			got, ok := ExtractTargets(Command{Binary: bin, Args: []string{a}})
			if !ok || len(got) != 0 {
				t.Errorf("ExtractTargets(%s %q) = %v, %v; want no targets", bin, a, got, ok)
			}
		}
	}
	for _, bin := range []string{"smbclient", "rpcclient", "/usr/bin/smbclient"} {
		got, ok := ExtractTargets(Command{Binary: bin, Args: []string{"//evil.com/x"}})
		if !ok || len(got) != 1 || got[0] != "evil.com" {
			t.Errorf("ExtractTargets(%s //evil.com/x) = %v, %v", bin, got, ok)
		}
	}
}

func TestUNCPayloadsAndPathsInScopeStayAllowedForNonSMBTools(t *testing.T) {
	stubEnumFixtureResolver(t)
	scope, err := ParseScope(strings.NewReader("10.0.0.0/24\ncorp.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Command{
		{Binary: "curl", Args: []string{"-d", "file=//etc/passwd", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-d", "file=\\\\windows\\win.ini", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--data-raw", "//x", "https://corp.example/"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied an in-scope non-SMB command: %q", c.Binary, c.Args, d.Reason)
		}
	}
	// A "//" value to a write flag is an absolute output path, not an SMB target.
	// The classifier and target extraction must still not treat it as UNC (only
	// the in-scope URL is a target), but the file-access recheck correctly denies
	// the absolute path, so the full seam denies it with that reason.
	for _, c := range []Command{
		{Binary: "curl", Args: []string{"-o", "//x", "http://10.0.0.5/"}},
		{Binary: "wget", Args: []string{"-O", "//tmp/x", "http://10.0.0.5/"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied a non-SMB command: %q", c.Binary, c.Args, d.Reason)
		}
		if got, ok := ExtractTargets(c); !ok || !reflect.DeepEqual(got, []string{"10.0.0.5"}) {
			t.Errorf("ExtractTargets(%q %v) = %v, %v; want [10.0.0.5] true", c.Binary, c.Args, got, ok)
		}
		d := g.Authorize(context.Background(), c)
		if d.Allowed || !strings.Contains(d.Reason, "file path outside the working directory") {
			t.Errorf("Authorize(%q %v) = %+v; want a file-access denial", c.Binary, c.Args, d)
		}
	}
}

// Three or more leading separators are still a UNC path to smbclient and
// rpcclient, so they must not be skipped as a filesystem path.
func TestSMBEnumManySeparatorUNCDeniedByGate(t *testing.T) {
	g := newSMBGate(t)
	for _, c := range []Command{
		{Binary: "smbclient", Args: []string{"///evil.com/share", "-N", "-W", "corp.example"}},
		{Binary: "smbclient", Args: []string{"////evil.com/share", "-N"}},
		{Binary: "smbclient", Args: []string{"\\\\\\evil.com\\share", "-N"}},
		{Binary: "smbclient", Args: []string{"///8.8.8.8/share", "-N", "-I", "10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"///evil.com", "-N", "-I", "10.0.0.5"}},
		{Binary: "rpcclient", Args: []string{"////evil.com", "-N", "-I", "10.0.0.5"}},
		{Binary: "smbclient", Args: []string{"///", "-N", "-W", "corp.example"}},
	} {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("Authorize(%q %v) allowed a many-separator UNC target", c.Binary, c.Args)
		}
	}
	if d := g.Authorize(context.Background(), Command{Binary: "smbclient", Args: []string{"///10.0.0.5/share", "-N"}}); !d.Allowed {
		t.Errorf("an in-scope many-separator UNC must be allowed: %q", d.Reason)
	}
}

// The glued-flag rule is bounded to smbclient and rpcclient host flags.
func TestSMBEnumGluedRuleBounded(t *testing.T) {
	for _, c := range []Command{
		{Binary: "nbtscan", Args: []string{"-t500", "10.0.0.5"}},
		{Binary: "showmount", Args: []string{"-e", "10.0.0.5"}},
		{Binary: "host", Args: []string{"-tmx", "corp.example"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied: %q", c.Binary, c.Args, d.Reason)
		}
	}
}
