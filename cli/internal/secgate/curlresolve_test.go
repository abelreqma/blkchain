package secgate

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestCurlResolveTargetsAndDNSOverride(t *testing.T) {
	cmd := Command{Binary: "curl", Args: []string{"--resolve", "app.example.test:443:[2001:db8::10]", "https://app.example.test/"}}
	resolves, err := CurlResolveArgs(cmd.Args)
	if err != nil || !reflect.DeepEqual(resolves, []CurlResolve{{Host: "app.example.test", Port: 443, Address: "2001:db8::10"}}) {
		t.Fatalf("resolve = %+v, %v", resolves, err)
	}
	targets, ok := ExtractTargets(cmd)
	if !ok || !reflect.DeepEqual(targets, []string{"app.example.test", "2001:db8::10"}) {
		t.Fatalf("targets = %v, ok=%t", targets, ok)
	}
	scope, err := ParseScope(strings.NewReader("app.example.test\n2001:db8::10\n"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	lookup := func(string) ([]net.IP, error) {
		called = true
		return []net.IP{net.ParseIP("2001:db8::20")}, nil
	}
	if host, ip, bad := resolveScopeViolationWith(scope, cmd, lookup, nil); bad || host != "" || ip != "" || called {
		t.Fatalf("override resolved through DNS: host=%q ip=%q bad=%t called=%t", host, ip, bad, called)
	}
	cmd.Args = []string{"--resolve", "app.example.test:443:[2001:db8::20]", "https://app.example.test/"}
	targets, ok = ExtractTargets(cmd)
	if !ok || len(targets) != 2 || scope.InScope(targets[1]) {
		t.Fatal("out-of-scope connected IPv6 address passed")
	}
}
