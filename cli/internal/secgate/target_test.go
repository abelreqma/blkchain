package secgate

import (
	"reflect"
	"testing"
)

func TestExtractTargetsURLUserinfoSpoof(t *testing.T) {
	// The real host is evil.com; allowed.example.com is only userinfo.
	got, _ := ExtractTargets(Command{Binary: "curl", Args: []string{"http://allowed.example.com@evil.com/x"}})
	if !contains(got, "evil.com") {
		t.Errorf("want evil.com extracted as the host, got %v", got)
	}
	if contains(got, "allowed.example.com") {
		t.Errorf("userinfo host must NOT be treated as a target, got %v", got)
	}
}

func TestExtractTargetsIPAndHostPort(t *testing.T) {
	got, _ := ExtractTargets(Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5", "host.example.com:8443"}})
	if !contains(got, "10.0.0.5") || !contains(got, "host.example.com") {
		t.Errorf("want 10.0.0.5 and host.example.com, got %v", got)
	}
	if contains(got, "80") || contains(got, "-p") {
		t.Errorf("flags/ports must not be targets, got %v", got)
	}
}

func TestExtractTargetsNoneFound(t *testing.T) {
	if got, ok := ExtractTargets(Command{Binary: "echo", Args: []string{"hello", "--flag"}}); got != nil || !ok {
		t.Errorf("want (nil, true), got (%v, %v)", got, ok)
	}
}

func TestExtractTargetsDedupAndLower(t *testing.T) {
	got, _ := ExtractTargets(Command{Binary: "x", Args: []string{"Host.Example.COM", "host.example.com"}})
	want := []string{"host.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractTargetsMatrix(t *testing.T) {
	cases := []struct {
		name string
		bin  string
		args []string
		want []string
		ok   bool
	}{
		{"in-scope plus flag-embedded evil", "curl", []string{"in-scope.example.com", "--url=http://evil.com"}, []string{"in-scope.example.com", "evil.com"}, true},
		{"flag url", "curl", []string{"--url=http://evil.com"}, []string{"evil.com"}, true},
		{"flag short embedded scheme", "curl", []string{"-Hx=http://evil.com"}, []string{"evil.com"}, true},
		{"flag prefix colon scheme", "curl", []string{"-Hhost:http://evil.com"}, []string{"evil.com"}, true},
		{"flag equals bare host", "tool", []string{"--target=evil.com"}, []string{"evil.com"}, true},
		{"flag equals comma list", "tool", []string{"--targets=a.example.com,b.example.com"}, []string{"a.example.com", "b.example.com"}, true},
		{"cidr", "nmap", []string{"10.0.0.0/24"}, nil, false},
		{"ipv6 cidr", "nmap", []string{"fe80::/10"}, nil, false},
		{"ip range", "nmap", []string{"10.0.0.1-5"}, nil, false},
		{"malformed ip", "nmap", []string{"10.0.0.256"}, nil, false},
		{"host with mask", "nmap", []string{"evil.com/24"}, []string{"evil.com"}, false},
		{"ssh user at host", "ssh", []string{"user@evil.com"}, []string{"evil.com"}, true},
		{"scp user host path", "scp", []string{"user@evil.com:/tmp"}, []string{"evil.com"}, true},
		{"scp host path", "scp", []string{"evil.com:/tmp/x"}, []string{"evil.com"}, true},
		{"user at last at wins", "ssh", []string{"a@b@evil.com"}, []string{"evil.com"}, true},
		{"user at empty host", "ssh", []string{"user@"}, nil, false},
		{"path and query", "curl", []string{"evil.com/admin?x=1"}, []string{"evil.com"}, true},
		{"query only", "curl", []string{"evil.com?x=1"}, []string{"evil.com"}, true},
		{"fragment", "curl", []string{"evil.com#frag"}, []string{"evil.com"}, true},
		{"at in path does not hide host", "curl", []string{"evil.com/a@allowed.example.com"}, []string{"evil.com"}, true},
		{"trailing dot", "curl", []string{"evil.com."}, []string{"evil.com"}, true},
		{"trailing dot url", "curl", []string{"http://evil.com./x"}, []string{"evil.com"}, true},
		{"comma list", "curl", []string{"evil.com,other.com"}, []string{"evil.com", "other.com"}, true},
		{"url then comma host", "curl", []string{"http://a.example.com,b.example.com"}, []string{"a.example.com", "b.example.com"}, true},
		{"userinfo spoof", "curl", []string{"http://allowed.example.com@evil.com/x"}, []string{"evil.com"}, true},
		{"userinfo with port spoof", "curl", []string{"http://allowed.example.com:80@evil.com:8080/x"}, []string{"evil.com"}, true},
		{"backslash userinfo", "curl", []string{`http://allowed.example.com\@evil.com/`}, nil, false},
		{"scheme without host", "curl", []string{"file:///etc/passwd"}, nil, false},
		{"bare scheme separator", "curl", []string{"://evil.com"}, nil, false},
		{"nested url in query", "curl", []string{"http://a.example.com/r?u=http://evil.com"}, []string{"a.example.com", "evil.com"}, true},
		{"ipv6 port", "curl", []string{"[::1]:8080"}, []string{"::1"}, true},
		{"ipv6 url", "curl", []string{"http://[::1]:8080/x"}, []string{"::1"}, true},
		{"bare ip", "ping", []string{"10.0.0.5"}, []string{"10.0.0.5"}, true},
		{"bare localhost", "curl", []string{"in-scope.example.com", "localhost"}, []string{"in-scope.example.com", "localhost"}, true},
		{"localhost upper with path", "curl", []string{"LOCALHOST/x"}, []string{"localhost"}, true},
		{"localhost port", "curl", []string{"localhost:8100"}, []string{"localhost"}, true},
		{"localhost user at", "ssh", []string{"user@localhost"}, []string{"localhost"}, true},
		{"localhost url", "curl", []string{"http://user@localhost:6333/x"}, []string{"localhost"}, true},
		{"hex packed ip", "curl", []string{"in-scope.example.com", "0x7f000001"}, []string{"in-scope.example.com"}, false},
		{"hex packed ip upper", "curl", []string{"0X7F000001"}, nil, false},
		{"hex packed ip with port", "curl", []string{"0x7f000001:80"}, nil, false},
		{"decimal packed ip", "curl", []string{"in-scope.example.com", "2130706433"}, []string{"in-scope.example.com"}, false},
		{"decimal packed ip path", "curl", []string{"2130706433/x"}, nil, false},
		{"top-ports not flagged", "nmap", []string{"--top-ports", "1000", "in-scope.example.com"}, []string{"in-scope.example.com"}, true},
		{"port flag not flagged", "nmap", []string{"-p", "8080", "in-scope.example.com"}, []string{"in-scope.example.com"}, true},
		{"seven digits not flagged", "nmap", []string{"--rate", "5000000", "in-scope.example.com"}, []string{"in-scope.example.com"}, true},
		{"version flag", "nmap", []string{"--version"}, nil, true},
		{"words paths and ports", "ls", []string{"-la", "/etc", "./x", "../y", "src/main", "80", "~"}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ExtractTargets(Command{Binary: tc.bin, Args: tc.args})
			if !reflect.DeepEqual(got, tc.want) || ok != tc.ok {
				t.Errorf("args %q: got (%v, %v), want (%v, %v)", tc.args, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestExtractTargetsUnparseableURLIsUnresolved(t *testing.T) {
	// Any partial targets are irrelevant; ok=false makes the gate deny.
	if _, ok := ExtractTargets(Command{Binary: "curl", Args: []string{"http://ev il.com"}}); ok {
		t.Errorf("want ok=false for an unparseable URL")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
