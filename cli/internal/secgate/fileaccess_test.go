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
			"ffuf -w relative wordlist (allowed; an absolute path is bounded, see httpenum_test.go)",
			Command{Binary: "ffuf", Args: []string{"-w", "wordlists/x"}},
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
		{"curl --data-urlencode @abs", Command{Binary: "curl", Args: []string{"--data-urlencode", "@/abs/.env", "http://h/"}}, true},
		{"curl --data-urlencode name@dotdot", Command{Binary: "curl", Args: []string{"--data-urlencode", "n@../x", "http://h/"}}, true},
		{"curl -D abs", Command{Binary: "curl", Args: []string{"-D", "/abs/audit.jsonl", "http://h/"}}, true},
		{"curl -c dotdot", Command{Binary: "curl", Args: []string{"-c", "../x", "http://h/"}}, true},
		{"curl --output-dir abs", Command{Binary: "curl", Args: []string{"-o", "out.txt", "--output-dir", "/abs", "http://h/"}}, true},
		{"curl --trace abs", Command{Binary: "curl", Args: []string{"--trace", "/abs/t", "http://h/"}}, true},
		{"curl --stderr dotdot", Command{Binary: "curl", Args: []string{"--stderr=../e", "http://h/"}}, true},
		{"wget -P abs", Command{Binary: "wget", Args: []string{"-P", "/abs", "http://h/"}}, true},
		{"wget -o dotdot", Command{Binary: "wget", Args: []string{"-o", "../log", "http://h/"}}, true},
		{"wget -a abs", Command{Binary: "wget", Args: []string{"-a", "/abs/log", "http://h/"}}, true},
		{"wget --post-file abs", Command{Binary: "wget", Args: []string{"--post-file=/etc/passwd", "http://h/"}}, true},
		{"wget abbreviated --dir", Command{Binary: "wget", Args: []string{"--dir=/abs", "http://h/"}}, true},
		{"curl -K relative", Command{Binary: "curl", Args: []string{"-K", "anything", "http://h/"}}, true},
		{"curl --config abs", Command{Binary: "curl", Args: []string{"--config", "/abs", "http://h/"}}, true},
		{"curl --config= relative", Command{Binary: "curl", Args: []string{"--config=cfg", "http://h/"}}, true},
		{"wget --config relative", Command{Binary: "wget", Args: []string{"--config", "x", "http://h/"}}, true},
		{"wget abbreviated --conf", Command{Binary: "wget", Args: []string{"--conf=x", "http://h/"}}, true},
		{"wget -e execute", Command{Binary: "wget", Args: []string{"-e", "output_document=/abs", "http://h/"}}, true},
		{"curl bundle -so abs", Command{Binary: "curl", Args: []string{"-so", "/abs/x", "http://h/"}}, true},
		{"curl glued -o abs", Command{Binary: "curl", Args: []string{"-o/abs/x", "http://h/"}}, true},
		{"curl bundle -sK", Command{Binary: "curl", Args: []string{"-sK", "cfg", "http://h/"}}, true},
		{"curl -F =< dotdot", Command{Binary: "curl", Args: []string{"-F", "f=<../x", "http://h/"}}, true},
		{"curl --json @abs", Command{Binary: "curl", Args: []string{"--json", "@/abs/x", "http://h/"}}, true},
		{"curl -w @abs", Command{Binary: "curl", Args: []string{"-w", "@/abs/x", "http://h/"}}, true},
		{"nmap -oN=dotdot", Command{Binary: "nmap", Args: []string{"-oN=../x", "10.0.0.5"}}, true},
		{"curl --data-urlencode literal (allowed)", Command{Binary: "curl", Args: []string{"--data-urlencode", "q=hello", "http://h/"}}, false},
		{"curl -s -o relative (allowed)", Command{Binary: "curl", Args: []string{"-s", "-o", "out.txt", "http://h/"}}, false},
		{"curl bundle -so relative (allowed)", Command{Binary: "curl", Args: []string{"-so", "out.txt", "http://h/"}}, false},
		{"wget -O relative (allowed)", Command{Binary: "wget", Args: []string{"-O", "out", "http://h/"}}, false},
		{"wget -q plain (allowed)", Command{Binary: "wget", Args: []string{"-q", "http://h/"}}, false},
		{"cat positional read (not a write flag)", Command{Binary: "cat", Args: []string{"/etc/passwd"}}, false},
		{"ss -D abs", Command{Binary: "ss", Args: []string{"-D", "/abs/x"}}, true},
		{"ss -tn plain (allowed)", Command{Binary: "ss", Args: []string{"-tn"}}, false},
		{"ncat -o dotdot", Command{Binary: "ncat", Args: []string{"-o", "../x", "10.0.0.5", "22"}}, true},
		{"nc -o abs", Command{Binary: "nc", Args: []string{"-o", "/abs/x", "10.0.0.5", "22"}}, true},
		{"wget --hsts-file abs", Command{Binary: "wget", Args: []string{"--hsts-file=/abs/h", "http://h/"}}, true},
		{"ncat plain (allowed)", Command{Binary: "ncat", Args: []string{"10.0.0.5", "22"}}, false},
		{"nmap --oN abs", Command{Binary: "nmap", Args: []string{"--oN", "/abs/x", "10.0.0.5"}}, true},
		{"nmap --oN dotdot", Command{Binary: "nmap", Args: []string{"--oN", "../audit.jsonl", "10.0.0.5"}}, true},
		{"nmap --oX= abs", Command{Binary: "nmap", Args: []string{"--oX=/abs", "10.0.0.5"}}, true},
		{"nmap --oG abs", Command{Binary: "nmap", Args: []string{"--oG", "/abs", "10.0.0.5"}}, true},
		{"nmap --oA abs", Command{Binary: "nmap", Args: []string{"--oA", "/abs", "10.0.0.5"}}, true},
		{"nmap --oS abs", Command{Binary: "nmap", Args: []string{"--oS", "/abs", "10.0.0.5"}}, true},
		{"nmap --oJ abs", Command{Binary: "nmap", Args: []string{"--oJ", "/abs", "10.0.0.5"}}, true},
		{"nmap -oN abs regression", Command{Binary: "nmap", Args: []string{"-oN", "/abs/x", "10.0.0.5"}}, true},
		{"nmap -oN glued abs", Command{Binary: "nmap", Args: []string{"-oN/abs/x", "10.0.0.5"}}, true},
		{"nmap -oN relative (allowed)", Command{Binary: "nmap", Args: []string{"-oN", "out.txt", "10.0.0.5"}}, false},
		{"nmap --oN relative (allowed)", Command{Binary: "nmap", Args: []string{"--oN", "out.txt", "10.0.0.5"}}, false},
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
