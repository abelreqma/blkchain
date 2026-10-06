package secgate

import "testing"

// TestMasscanFileFlagsDeniedInEverySpelling is the matcher's reason for
// existing: masscan lowercases a flag name and strips every '-' and '_' before
// comparing it, so a literal denylist would catch one spelling and miss the
// rest.
func TestMasscanFileFlagsDeniedInEverySpelling(t *testing.T) {
	bound := []string{"-p", "80", "--rate", "100"}
	for _, flag := range []string{
		"--excludefile", "--exclude-file", "--exclude_file", "--EXCLUDEFILE",
		"--ExcludeFile", "-excludefile", "--conf", "-c", "--CONF",
		"--resume", "--re-sume", "--includefile", "-iL", "-il", "--include-file",
		"--readscan", "--read-scan", "--pcap", "--pcap-payloads",
		"--output-filename", "--outputfilename", "-oX", "-oJ", "-oL", "-oG", "-oB",
		"--rotate-dir", "--nmap-data-dir",
	} {
		args := append(append([]string{}, bound...), flag, "value", "192.0.2.1")
		denied(t, "masscan "+flag, Classify(Command{Binary: "masscan", Args: args}))
		glued := append(append([]string{}, bound...), flag+"=value", "192.0.2.1")
		denied(t, "masscan "+flag+"=value", Classify(Command{Binary: "masscan", Args: glued}))
	}
}

// TestMasscanScanFormsAllowed keeps the tool usable: the flags a bounded sweep
// needs are untouched, including the ones whose normalized names sit near a
// denied one.
func TestMasscanScanFormsAllowed(t *testing.T) {
	for _, args := range [][]string{
		{"-p", "80,443", "--rate", "100", "192.0.2.1"},
		{"-p80", "--rate=100", "192.0.2.0/24"},
		{"--ports", "1-1024", "--rate", "50", "--banners", "192.0.2.1"},
		{"--top-ports", "100", "--rate", "50", "--open-only", "192.0.2.1"},
		// output-format is not output-filename, and router-mac is not readscan.
		{"-p", "80", "--rate", "100", "--output-format", "json", "192.0.2.1"},
		{"-p", "80", "--rate", "100", "--router-mac", "00:11:22:33:44:55", "192.0.2.1"},
		{"-p", "80", "--rate", "100", "--interface", "eth0", "192.0.2.1"},
	} {
		allowed(t, "masscan "+join(args), Classify(Command{Binary: "masscan", Args: args}))
	}
	// The matcher applies to masscan only.
	allowed(t, "nmap --excludefile", Classify(Command{
		Binary: "nmap", Args: []string{"-p", "80", "--excludefile", "x", "192.0.2.1"}}))
}

// TestNormalizeMasscanFlag pins the normalization itself, including the forms
// that must not normalize to a flag at all.
func TestNormalizeMasscanFlag(t *testing.T) {
	for arg, want := range map[string]string{
		"--exclude-file": "excludefile",
		"--EXCLUDE_FILE": "excludefile",
		"-oX":            "ox",
		"--rate=100":     "rate",
		"192.0.2.1":      "",
		"":               "",
		"-":              "",
		"--":             "",
		"192.0.2.0/24":   "",
		"--top-ports":    "topports",
	} {
		if got := normalizeMasscanFlag(arg); got != want {
			t.Errorf("normalizeMasscanFlag(%q) = %q, want %q", arg, got, want)
		}
	}
}
