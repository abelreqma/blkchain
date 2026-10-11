package secgate

import "testing"

// The forms a dependency or image scan needs: a local path or a staged archive, reporting JSON on stdout.
func TestVulnScannersPermitTheReportingForms(t *testing.T) {
	for _, c := range []Command{
		{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-r", "."}},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-L", "go.mod"}},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "--format=json", "--offline", "-r", "app"}},
		{Binary: "osv-scanner", Args: []string{"scan", "image", "--archive", "--format", "json", "image.tar"}},
		{Binary: "grype", Args: []string{"dir:.", "-o", "json"}},
		{Binary: "grype", Args: []string{"sbom:sbom.json", "-o", "json", "--quiet"}},
		{Binary: "grype", Args: []string{"oci-archive:image.tar", "-o", "json", "--only-fixed"}},
		{Binary: "grype", Args: []string{"purl:packages.txt", "-o", "json"}},
		{Binary: "grype", Args: []string{"cpe:2.3:a:example:package:1:*:*:*:*:*:*:*", "-o", "json"}},
		{Binary: "grype", Args: []string{"-o", "json", "--fail-on", "high", "dir:app"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("%s %v denied: %s", c.Binary, c.Args, d.Reason)
		}
	}
}

func TestOSVScannerDeniesEveryAuditClass(t *testing.T) {
	for name, args := range map[string][]string{
		// code execution
		"call analysis runs build scripts":   {"scan", "source", "--call-analysis", "rust", "-r", "."},
		"call analysis in the = form":        {"scan", "source", "--call-analysis=rust", "-r", "."},
		"plugins select the extractors":      {"scan", "source", "--experimental-plugins", "x", "-r", "."},
		"no-default-plugins selects as well": {"scan", "source", "--experimental-no-default-plugins", "-r", "."},
		"mcp runs a service":                 {"experimental-mcp"},
		// config indirection
		"config replaces the configuration": {"scan", "source", "--config", "osv.toml", "-r", "."},
		// network destination
		"serve opens a listener":        {"scan", "source", "--serve", "-r", "."},
		"port binds the listener":       {"scan", "source", "--port", "9000", "-r", "."},
		"data source names a host":      {"scan", "source", "--data-source", "native", "-r", "."},
		"maven registry names a host":   {"scan", "source", "--maven-registry", "http://evil", "-r", "."},
		"database download fetches":     {"scan", "source", "--download-offline-databases", "-r", "."},
		"scan image reaches a registry": {"scan", "image", "alpine:3.23"},
		// write: rewriting the tree under scan
		"fix rewrites the manifest":    {"fix", "-M", "pom.xml", "-L", "go.mod"},
		"update rewrites the manifest": {"update", "-M", "pom.xml"},
		// file read outside the scratch directory
		"absolute operand":        {"scan", "source", "-r", "/etc"},
		"parent-relative operand": {"scan", "source", "-r", "../../etc"},
	} {
		if d := Classify(Command{Binary: "osv-scanner", Args: args}); d.Allowed {
			t.Errorf("%s: osv-scanner %v was allowed", name, args)
		}
	}
}

func TestGrypeDeniesEveryAuditClass(t *testing.T) {
	for name, args := range map[string][]string{
		// code execution: a template file decides what runs and what is rendered
		"template long":   {"dir:.", "-o", "template", "--template", "t.tmpl"},
		"template short":  {"dir:.", "-o", "template", "-t", "t.tmpl"},
		"template = form": {"dir:.", "--template=t.tmpl"},
		// config indirection
		"config long":  {"dir:.", "--config", "grype.yaml"},
		"config short": {"dir:.", "-c", "grype.yaml"},
		"profile":      {"dir:.", "--profile", "p"},
		// network destination
		"registry scheme":     {"registry:alpine:3.23", "-o", "json"},
		"docker scheme":       {"docker:alpine:3.23", "-o", "json"},
		"podman scheme":       {"podman:alpine:3.23", "-o", "json"},
		"oci-registry scheme": {"oci-registry:alpine:3.23", "-o", "json"},
		"schemeless operand":  {"alpine:3.23", "-o", "json"},
		// state change
		"db subcommand":     {"db", "update"},
		"config subcommand": {"config"},
		// file read outside the scratch directory
		"absolute dir":        {"dir:/etc", "-o", "json"},
		"parent-relative dir": {"dir:../../etc", "-o", "json"},
		"absolute sbom":       {"sbom:/root/sbom.json", "-o", "json"},
		"absolute purl file":  {"purl:/etc/passwd", "-o", "json"},
		"parent purl file":    {"purl:../packages.txt", "-o", "json"},
	} {
		if d := Classify(Command{Binary: "grype", Args: args}); d.Allowed {
			t.Errorf("%s: grype %v was allowed", name, args)
		}
	}
}

// The operand walk skips a flag's value, so a value is not read as an operand and an operand after one is still seen.
func TestVulnScannerOperandWalkSkipsFlagValues(t *testing.T) {
	if d := Classify(Command{Binary: "grype", Args: []string{"--name", "alpine:3.23", "dir:."}}); !d.Allowed {
		t.Errorf("a --name value was read as an operand: %s", d.Reason)
	}
	if d := Classify(Command{Binary: "grype", Args: []string{"--name", "x", "registry:alpine"}}); d.Allowed {
		t.Error("an operand after a value-taking flag was not checked")
	}
	if d := Classify(Command{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "/etc", "-r", "."}}); !d.Allowed {
		t.Errorf("a --format value was read as a path operand: %s", d.Reason)
	}
	if d := Classify(Command{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-r", "/etc"}}); d.Allowed {
		t.Error("an operand after a value-taking flag was not checked")
	}
}

// A report path inside the scratch directory stays allowed; one that escapes it is refused.
func TestVulnScannerReportPathsAreBoundedNotDenied(t *testing.T) {
	for _, c := range []Command{
		{Binary: "grype", Args: []string{"dir:.", "-o", "json", "--file", "report.json"}},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "-r", ".", "--output-file", "report.json"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("%s %v denied: %s", c.Binary, c.Args, d.Reason)
		}
		if arg, bad := FileAccessViolation(c); bad {
			t.Errorf("%s %v: in-scratch report path %q rejected", c.Binary, c.Args, arg)
		}
	}
	for _, c := range []Command{
		{Binary: "grype", Args: []string{"dir:.", "-o", "json", "--file", "../report.json"}},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "-r", ".", "--output-file", "/tmp/report.json"}},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "-L", "../../etc/passwd"}},
		{Binary: "osv-scanner", Args: []string{"scan", "image", "--archive=/etc/passwd"}},
		{Binary: "osv-scanner", Args: []string{"scan", "image", "--archive", "../image.tar"}},
		{Binary: "grype", Args: []string{"dir:.", "--vex", "/etc/vex.json"}},
		{Binary: "grype", Args: []string{"dir:.", "--exclude", "/etc/**"}},
	} {
		if _, bad := FileAccessViolation(c); !bad {
			t.Errorf("%s %v: escaping path accepted", c.Binary, c.Args)
		}
	}
}

// The denials are per-binary, so one scanner's flag name does not deny the same spelling elsewhere.
func TestVulnScannerDenialsDoNotLeakToOtherBinaries(t *testing.T) {
	if d := Classify(Command{Binary: "nmap", Args: []string{"-p", "443", "--data-source", "x", "10.0.0.5"}}); !d.Allowed {
		if d.Reason == "nmap --data-source names a metadata host the scope check never reads" {
			t.Error("an osv-scanner denial applied to nmap")
		}
	}
	if d := Classify(Command{Binary: "curl", Args: []string{"--profile", "p", "http://10.0.0.5"}}); !d.Allowed {
		t.Errorf("a grype denial applied to curl: %s", d.Reason)
	}
}

// The scanners address no host, so the extractor returns a verified-empty target set rather than reading a source scheme as one.
func TestVulnScannersHaveNoExtractableTarget(t *testing.T) {
	for _, c := range []Command{
		{Binary: "grype", Args: []string{"dir:.", "-o", "json"}},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "-r", "."}},
	} {
		targets, nets, ok := ExtractTargetSet(c)
		if !ok {
			t.Errorf("%s %v reported an unverifiable target set", c.Binary, c.Args)
		}
		if len(targets) > 0 || len(nets) > 0 {
			t.Errorf("%s %v yielded targets %v and networks %v", c.Binary, c.Args, targets, nets)
		}
	}
}

// An output filename is not a destination, so reading one as a host would deny every curl -o and leave no way to stage material for a scan.
func TestOutputPathValuesAreNotReadAsTargets(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"-s", "-o", "go.mod", "http://10.0.0.5/go.mod"}, []string{"10.0.0.5"}},
		{[]string{"-s", "--output=package-lock.json", "http://10.0.0.5/x"}, []string{"10.0.0.5"}},
		{[]string{"-s", "-o", "sbom.cdx.json", "-D", "headers.txt", "http://10.0.0.5/s"}, []string{"10.0.0.5"}},
		{[]string{"-s", "-c", "jar.txt", "--etag-save", "etag.txt", "http://10.0.0.5/"}, []string{"10.0.0.5"}},
	} {
		targets, _, ok := ExtractTargetSet(Command{Binary: "curl", Args: tc.args})
		if !ok {
			t.Errorf("curl %v reported an unverifiable target set", tc.args)
			continue
		}
		if len(targets) != len(tc.want) {
			t.Errorf("curl %v yielded %v, want %v", tc.args, targets, tc.want)
			continue
		}
		for i := range tc.want {
			if targets[i] != tc.want[i] {
				t.Errorf("curl %v yielded %v, want %v", tc.args, targets, tc.want)
				break
			}
		}
	}
}

// Skipping an output value must not hide a real destination: a proxy flag is still extracted and the path is still bounded to the scratch directory.
func TestOutputPathSkipDoesNotHideADestination(t *testing.T) {
	targets, _, ok := ExtractTargetSet(Command{Binary: "curl",
		Args: []string{"-s", "-o", "out.json", "-x", "http://198.51.100.9:8080", "http://10.0.0.5/"}})
	if !ok {
		t.Fatal("the target set is unverifiable")
	}
	var sawProxy, sawHost bool
	for _, t2 := range targets {
		switch t2 {
		case "198.51.100.9":
			sawProxy = true
		case "10.0.0.5":
			sawHost = true
		}
	}
	if !sawProxy {
		t.Errorf("the proxy destination was not extracted: %v", targets)
	}
	if !sawHost {
		t.Errorf("the request host was not extracted: %v", targets)
	}
	if _, bad := FileAccessViolation(Command{Binary: "curl",
		Args: []string{"-s", "-o", "../escape.json", "http://10.0.0.5/"}}); !bad {
		t.Error("an escaping output path was accepted")
	}
	if _, bad := FileAccessViolation(Command{Binary: "curl",
		Args: []string{"-s", "-o", "go.mod", "http://10.0.0.5/"}}); bad {
		t.Error("an in-scratch output path was rejected")
	}
}

// The skip is per binary, so a tool with no output-path flags listed is unaffected.
func TestOutputPathSkipIsPerBinary(t *testing.T) {
	targets, _, ok := ExtractTargetSet(Command{Binary: "nmap", Args: []string{"-p", "80", "-oN", "scan.txt", "10.0.0.5"}})
	if !ok {
		t.Fatal("the target set is unverifiable")
	}
	found := false
	for _, t2 := range targets {
		if t2 == "10.0.0.5" {
			found = true
		}
	}
	if !found {
		t.Errorf("nmap's host was not extracted: %v", targets)
	}
}
