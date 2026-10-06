package secgate

import "testing"

// toolgate_test.go is the two-sided audit of the tools the runner image gained:
// each hostile spelling must be denied, and the legitimate invocation each
// persona actually needs must still pass. A denial test alone would be satisfied
// by denying the tool outright.

func allowed(t *testing.T, label string, d Decision) {
	t.Helper()
	if !d.Allowed {
		t.Errorf("%s was denied: %s", label, d.Reason)
	}
}

func denied(t *testing.T, label string, d Decision) {
	t.Helper()
	if d.Allowed {
		t.Errorf("%s was allowed", label)
	}
}

// TestSudoListingIsTheOnlyPermittedSudo pins the exception that makes the local
// persona's first enumeration step possible. sudo stays denied as an
// exec-wrapper everywhere else.
func TestSudoListingIsTheOnlyPermittedSudo(t *testing.T) {
	for _, args := range [][]string{{"-l"}, {"-ln"}, {"-nl"}, {"-n", "-l"}} {
		c := Command{Binary: "sudo", Args: args}
		allowed(t, "sudo listing (external classifier)", Classify(c))
		allowed(t, "sudo listing (local classifier)", ClassifyLocal(c))
	}
	for _, args := range [][]string{
		nil,
		{"-l", "/usr/bin/id"},
		{"-u", "root", "id"},
		{"id"},
		{"-i"},
		{"-s"},
		{"-l", "-l"},
		{"-E", "-l"},
		{"-n", "-l", "id"},
		{"--list", "id"},
		{"-ln", "bash"},
	} {
		c := Command{Binary: "sudo", Args: args}
		denied(t, "sudo with args "+join(args)+" (external classifier)", Classify(c))
		denied(t, "sudo with args "+join(args)+" (local classifier)", ClassifyLocal(c))
	}
}

// TestGdbInspectionFlagsOnly keeps gdb a static inspector. -ex runs gdb
// commands, which include shell; -x runs a command file; -p attaches to a live
// process; --args and --write turn inspection into execution and patching.
func TestGdbInspectionFlagsOnly(t *testing.T) {
	for _, args := range [][]string{
		{"-ex", "shell id", "/usr/bin/sudo"},
		{"--ex=shell id", "/usr/bin/sudo"},
		{"-x", "/work/script.gdb", "/usr/bin/sudo"},
		{"--command=/work/script.gdb", "/usr/bin/sudo"},
		{"--comm=/work/script.gdb", "/usr/bin/sudo"},
		{"-ix", "/work/early.gdb", "/usr/bin/sudo"},
		{"--init-command=/work/early.gdb", "/usr/bin/sudo"},
		{"-p", "1"},
		{"--pid=1"},
		{"--args", "/usr/bin/sudo", "-l"},
		{"--write", "/usr/bin/sudo"},
		{"-eval-command=shell id", "/usr/bin/sudo"},
	} {
		denied(t, "gdb "+join(args), Classify(Command{Binary: "gdb", Args: args}))
	}
	for _, args := range [][]string{
		{"-nx", "--version"},
		{"-nx", "-q", "-batch", "/usr/bin/sudo"},
		{"--batch", "--nx", "/usr/bin/sudo"},
		{"-n", "--batch", "/usr/bin/sudo"},
	} {
		allowed(t, "gdb "+join(args), Classify(Command{Binary: "gdb", Args: args}))
	}
}

// TestRequiredFlagsCloseDefaultOpenPaths covers the requirements that exist
// because a tool's default behaviour opens an execution or disclosure path.
func TestRequiredFlagsCloseDefaultOpenPaths(t *testing.T) {
	// gdb reads an init file from HOME, which is the writable scratch directory.
	for _, args := range [][]string{{"--version"}, {"-q", "-batch", "/usr/bin/sudo"}, nil} {
		denied(t, "gdb without -nx: "+join(args), Classify(Command{Binary: "gdb", Args: args}))
		denied(t, "gdb without -nx (local): "+join(args), ClassifyLocal(Command{Binary: "gdb", Args: args}))
	}
	// An unbounded capture never returns.
	denied(t, "tcpdump with no -c", Classify(Command{Binary: "tcpdump", Args: []string{"-i", "eth0"}}))
	allowed(t, "tcpdump -c", Classify(Command{Binary: "tcpdump", Args: []string{"-c", "50", "-i", "eth0"}}))
	allowed(t, "tcpdump bundled -nc", Classify(Command{Binary: "tcpdump", Args: []string{"-nc", "50", "-i", "eth0"}}))
	allowed(t, "tcpdump glued -c50", Classify(Command{Binary: "tcpdump", Args: []string{"-c50", "-i", "eth0"}}))
	// masscan defaults to a full port sweep at its own rate.
	for _, args := range [][]string{
		{"192.0.2.1"},
		{"-p", "80", "192.0.2.1"},
		{"--rate", "100", "192.0.2.1"},
		{"--ports", "80", "192.0.2.1"},
	} {
		denied(t, "masscan "+join(args), Classify(Command{Binary: "masscan", Args: args}))
	}
	for _, args := range [][]string{
		{"-p", "80,443", "--rate", "100", "192.0.2.1"},
		{"-p80", "--rate=100", "192.0.2.1"},
		{"--ports=80", "--rate", "100", "192.0.2.1"},
		{"--top-ports", "100", "--rate", "50", "192.0.2.1"},
	} {
		allowed(t, "masscan "+join(args), Classify(Command{Binary: "masscan", Args: args}))
	}
	// A binary with no requirement is untouched.
	allowed(t, "curl", Classify(Command{Binary: "curl", Args: []string{"http://192.0.2.1/"}}))
}

// TestBinutilsPluginIsDenied closes the one code-execution flag the analysis
// tools carry: --plugin loads a shared object into the tool.
func TestBinutilsPluginIsDenied(t *testing.T) {
	for _, bin := range []string{"nm", "objdump", "readelf", "strings"} {
		for _, args := range [][]string{
			{"--plugin", "/work/evil.so", "/usr/bin/sudo"},
			{"--plugin=/work/evil.so", "/usr/bin/sudo"},
			{"--plug=/work/evil.so", "/usr/bin/sudo"},
			{"-plugin", "/work/evil.so", "/usr/bin/sudo"},
		} {
			denied(t, bin+" "+join(args), Classify(Command{Binary: bin, Args: args}))
		}
	}
	// The inspection each persona actually runs still passes.
	allowed(t, "nm -D", Classify(Command{Binary: "nm", Args: []string{"-D", "/usr/bin/sudo"}}))
	allowed(t, "objdump -d", Classify(Command{Binary: "objdump", Args: []string{"-d", "/usr/bin/sudo"}}))
	allowed(t, "readelf -a", Classify(Command{Binary: "readelf", Args: []string{"-a", "/usr/bin/sudo"}}))
	allowed(t, "readelf -d", Classify(Command{Binary: "readelf", Args: []string{"-d", "/usr/bin/sudo"}}))
	allowed(t, "strings -n 8", Classify(Command{Binary: "strings", Args: []string{"-n", "8", "/usr/bin/sudo"}}))
}

// TestJohnExternalModeIsDenied closes john's code-execution flag: an external
// mode is compiled C that john runs.
func TestJohnExternalModeIsDenied(t *testing.T) {
	for _, args := range [][]string{
		{"--external=Filter", "/work/hashes"},
		{"--external", "Filter", "/work/hashes"},
		{"--extern=Filter", "/work/hashes"},
	} {
		denied(t, "john "+join(args), Classify(Command{Binary: "john", Args: args}))
	}
	allowed(t, "john --max-run-time", Classify(Command{
		Binary: "john", Args: []string{"--max-run-time=300", "--format=krb5tgs", "/work/hashes"}}))
}

// TestTcpdumpPostrotateCommandIsDenied closes tcpdump's code-execution flag. The
// bundled spelling is denied too, and a -w whose value happens to be "z" is not
// mistaken for it.
func TestTcpdumpPostrotateCommandIsDenied(t *testing.T) {
	for _, args := range [][]string{
		{"-z", "/bin/sh", "-i", "eth0"},
		{"-nz", "/bin/sh", "-i", "eth0"},
		{"-c", "1", "-z", "reboot"},
	} {
		denied(t, "tcpdump "+join(args), Classify(Command{Binary: "tcpdump", Args: args}))
	}
	for _, args := range [][]string{
		{"-c", "1", "-i", "eth0"},
		{"-c", "10", "-n", "-i", "eth0", "tcp", "port", "445"},
		// -w takes the next characters as its value, so this is an output file
		// named z, not the postrotate flag.
		{"-c", "1", "-wz", "-i", "eth0"},
	} {
		allowed(t, "tcpdump "+join(args), Classify(Command{Binary: "tcpdump", Args: args}))
	}
}

// TestFileAccessBoundsForNewTools is the two-sided file-access audit: a path
// that escapes the scratch working directory is refused, and the ordinary
// relative form each persona uses still passes.
func TestFileAccessBoundsForNewTools(t *testing.T) {
	escapes := []struct {
		binary string
		args   []string
	}{
		{"tcpdump", []string{"-c", "1", "-w", "/etc/capture.pcap"}},
		{"tcpdump", []string{"-c", "1", "-r", "../../etc/shadow"}},
		{"tcpdump", []string{"-c", "1", "-F", "/etc/shadow"}},
		{"sslscan", []string{"--xml=/etc/report.xml", "192.0.2.1"}},
		{"jq", []string{"-f", "/etc/shadow", "."}},
		// Two-value flags: the bound would check the variable name, not the path.
		{"jq", []string{"--rawfile", "x", "/etc/shadow", "."}},
		{"jq", []string{"--rawfile", "x", "local.txt", "."}},
		{"jq", []string{"--slurpfile", "x", "local.json", "."}},
		{"john", []string{"--max-run-time=60", "--pot=/etc/john.pot", "hashes"}},
		{"john", []string{"--max-run-time=60", "--wordlist=/etc/shadow", "hashes"}},
		{"openssl", []string{"enc", "-out", "/etc/evil", "-in", "x"}},
		{"openssl", []string{"req", "-keyout", "../../root/key.pem"}},
		{"file", []string{"-m", "/etc/shadow", "x"}},
		{"kinit", []string{"-c", "/tmp/outside/cc", "user"}},
		{"klist", []string{"-k", "/etc/krb5.keytab"}},
	}
	for _, c := range escapes {
		if arg, bad := FileAccessViolation(Command{Binary: c.binary, Args: c.args}); !bad {
			t.Errorf("%s %v escaped the scratch directory unchecked (arg %q)", c.binary, c.args, arg)
		}
	}
	fine := []struct {
		binary string
		args   []string
	}{
		{"tcpdump", []string{"-c", "100", "-w", "capture.pcap", "-i", "eth0"}},
		{"tcpdump", []string{"-c", "100", "-n", "-i", "eth0", "tcp", "port", "445"}},
		{"sslscan", []string{"--xml=report.xml", "192.0.2.1"}},
		{"jq", []string{"-r", ".items[].name"}},
		{"jq", []string{"-f", "filter.jq", "."}},
		{"john", []string{"--max-run-time=60", "--pot=cracked.pot", "hashes"}},
		{"openssl", []string{"s_client", "-connect", "192.0.2.1:443"}},
		{"file", []string{"/usr/bin/sudo"}},
		{"kinit", []string{"-c", "cc", "user"}},
		{"klist", []string{"-e"}},
	}
	for _, c := range fine {
		if arg, bad := FileAccessViolation(Command{Binary: c.binary, Args: c.args}); bad {
			t.Errorf("%s %v should be permitted, refused on %q", c.binary, c.args, arg)
		}
	}
}

// TestConfigIndirectionDeniedForNewTools closes the flags that hand control to a
// file which can itself set any other option.
func TestConfigIndirectionDeniedForNewTools(t *testing.T) {
	for _, c := range []struct {
		binary string
		args   []string
	}{
		{"john", []string{"--max-run-time=60", "--config=own.conf", "hashes"}},
		{"openssl", []string{"req", "-config", "own.cnf"}},
		{"file", []string{"-f", "paths.txt"}},
		{"file", []string{"--files-from", "paths.txt"}},
	} {
		if _, bad := FileAccessViolation(Command{Binary: c.binary, Args: c.args}); !bad {
			t.Errorf("%s %v should be denied as config indirection", c.binary, c.args)
		}
	}
}

// TestOpensslEngineIsDenied closes openssl's code-execution flag: -engine and
// -provider load a shared object into the process.
func TestOpensslEngineIsDenied(t *testing.T) {
	for _, args := range [][]string{
		{"req", "-engine", "/work/evil.so"},
		{"enc", "-engine=/work/evil.so"},
		{"s_client", "-provider", "/work/evil.so"},
		{"s_client", "-provider-path", "/work"},
	} {
		denied(t, "openssl "+join(args), Classify(Command{Binary: "openssl", Args: args}))
	}
	// The listing subcommand and ordinary TLS inspection still pass.
	allowed(t, "openssl engine (subcommand)", Classify(Command{Binary: "openssl", Args: []string{"engine"}}))
	allowed(t, "openssl s_client", Classify(Command{
		Binary: "openssl", Args: []string{"s_client", "-connect", "192.0.2.1:443", "-servername", "example.com"}}))
}

// TestHostUtilitiesAreReadOnly closes the state-changing spelling of the host
// utilities the local persona uses. The local profile has no binary allowlist,
// so the spelling is the only control, and an operator may list these in
// local_unattended_binaries.
func TestHostUtilitiesAreReadOnly(t *testing.T) {
	for _, c := range []struct {
		binary string
		args   []string
	}{
		{"hostname", []string{"attacker-controlled"}},
		{"hostname", []string{"-b", "newname"}},
		{"mount", []string{"/dev/sda1", "/mnt"}},
		{"mount", []string{"-o", "remount,rw", "/"}},
		{"crontab", []string{"-e"}},
		{"crontab", []string{"-r"}},
		{"crontab", []string{"own.cron"}},
		{"crontab", nil},
		{"crontab", []string{"-l", "-u", "root"}},
	} {
		denied(t, c.binary+" "+join(c.args), ClassifyLocal(Command{Binary: c.binary, Args: c.args}))
		denied(t, c.binary+" "+join(c.args)+" (external)", Classify(Command{Binary: c.binary, Args: c.args}))
	}
	for _, c := range []struct {
		binary string
		args   []string
	}{
		{"hostname", nil},
		{"hostname", []string{"-f"}},
		{"hostname", []string{"-i"}},
		{"mount", nil},
		{"crontab", []string{"-l"}},
		{"id", nil},
		{"uname", []string{"-a"}},
	} {
		allowed(t, c.binary+" "+join(c.args), ClassifyLocal(Command{Binary: c.binary, Args: c.args}))
	}
}
