package secgate

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Flag audit for dig (BIND 9.10.6, confirmed against the local binary with
// `dig -h` and by running each spelling below against a nonexistent file).
//
// Code exec: none. dig has no exec, plugin, or config-file option and no long
// options. Writes: none; output goes to stdout.
//
// File read: -f names a batch file whose every line is a full dig command line,
// including its own @server, -k, and -y. A batch line can therefore name a
// resolver the scope check never sees, so bounding the path is not enough and
// -f is denied outright (unlike dnsrecon -iL, whose lines are only domains).
//
// Credential indirection: -k reads a TSIG key file and -y takes the TSIG secret
// on the command line (visible in the process list and the audit log). Both are
// denied outright.
//
// Value-taking short letters are b c p q t x (plus f k y above). Letters 4 6 d h
// i m n u v take no value and may lead a bundle (-4f, -dmf, -nk all reach -f or
// -k). A value may be glued (-ffile), joined with '=' (dig 9.10.6 keeps the '=' in
// the value, other versions strip it), or separate.
//
// Target channel: the resolver is `@server`, anywhere on the line. The generic
// extractor already turns an '@'-led token into its host, so an out-of-scope
// resolver is denied. The queried name is data, not a connection target: when an
// explicit @server is present, positional tokens are not extracted.

var digDeniedSpellings = [][]string{
	// -f batch file
	{"@10.0.0.5", "-f", "queries"},
	{"@10.0.0.5", "-f", "/etc/passwd"},
	{"@10.0.0.5", "-f", "../x"},
	{"@10.0.0.5", "-fqueries"},
	{"@10.0.0.5", "-f=queries"},
	{"@10.0.0.5", "-4f", "queries"},
	{"@10.0.0.5", "-4fqueries"},
	{"@10.0.0.5", "-dmf", "queries"},
	{"@10.0.0.5", "-if", "queries"},
	{"@10.0.0.5", "-uf", "queries"},
	{"-f", "-"},
	// -k TSIG key file
	{"@10.0.0.5", "-k", "key", "corp.example"},
	{"@10.0.0.5", "-k", "/etc/passwd", "corp.example"},
	{"@10.0.0.5", "-kkey", "corp.example"},
	{"@10.0.0.5", "-k=key", "corp.example"},
	{"@10.0.0.5", "-4k", "key", "corp.example"},
	{"@10.0.0.5", "-4kkey", "corp.example"},
	{"@10.0.0.5", "-nk", "key", "corp.example"},
	// -y TSIG secret on argv
	{"@10.0.0.5", "-y", "hmac-sha256:name:c2VjcmV0", "corp.example"},
	{"@10.0.0.5", "-y", "name:c2VjcmV0", "corp.example"},
	{"@10.0.0.5", "-yname:c2VjcmV0", "corp.example"},
	{"@10.0.0.5", "-y=name:c2VjcmV0", "corp.example"},
	{"@10.0.0.5", "-4y", "name:c2VjcmV0", "corp.example"},
	{"@10.0.0.5", "-4yname:c2VjcmV0", "corp.example"},
}

func TestDigDeniedFlagsEverySpelling(t *testing.T) {
	for _, args := range digDeniedSpellings {
		d := Classify(Command{Binary: "dig", Args: args})
		if d.Allowed {
			t.Errorf("Classify(dig %v) allowed a denied flag", args)
		} else if !strings.Contains(d.Reason, "option not permitted") {
			t.Errorf("Classify(dig %v) denied for the wrong reason: %q", args, d.Reason)
		}
		if d := Classify(Command{Binary: "/usr/bin/dig", Args: args}); d.Allowed {
			t.Errorf("Classify(/usr/bin/dig %v) must be checked by base name", args)
		}
	}
}

func TestDigBenignInvocationsAllowed(t *testing.T) {
	benign := [][]string{
		{"@10.0.0.5", "corp.example"},
		{"corp.example", "@10.0.0.5"},
		{"corp.example"},
		{"+short", "mx", "corp.example"},
		{"@10.0.0.5", "-t", "axfr", "corp.example"},
		{"@10.0.0.5", "-tmx", "corp.example"},
		{"@10.0.0.5", "-x", "10.0.0.9"},
		{"@10.0.0.5", "-q", "corp.example", "-t", "ns"},
		{"@10.0.0.5", "-qkey.corp.example"},
		{"@10.0.0.5", "-4", "-p", "5353", "+time=2", "+tries=1", "corp.example"},
		{"@10.0.0.5", "-b", "10.0.0.9", "-c", "IN", "corp.example"},
		{"@10.0.0.5", "-6u", "corp.example", "any"},
	}
	for _, args := range benign {
		c := Command{Binary: "dig", Args: args}
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(dig %v) denied a benign command: %q", args, d.Reason)
		}
		if arg, bad := FileAccessViolation(c); bad {
			t.Errorf("FileAccessViolation(dig %v) denied a benign command (%q)", args, arg)
		}
	}
}

func digGate(t *testing.T, bins ...string) *Gate {
	t.Helper()
	scope, err := ParseScope(strings.NewReader("10.0.0.0/24\ncorp.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist(bins...)}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestDigServerIsScopeChecked(t *testing.T) {
	g := digGate(t, "dig")
	for _, args := range [][]string{
		{"@8.8.8.8", "x"},
		{"x", "@evil.com"},
		{"@8.8.8.8", "corp.example"},
		{"corp.example", "@evil.com"},
		{"@evil", "corp.example"},
		{"@10.0.0.5", "@evil.com", "corp.example"},
		{"+short", "@8.8.8.8", "corp.example"},
		{"@[2001:4860:4860::8888]", "corp.example"},
		{"@", "corp.example"},
		{"@10.0.0.0/24", "corp.example"},
		{"@8.8.8.8,10.0.0.5", "corp.example"},
	} {
		if d := g.Authorize(context.Background(), Command{Binary: "dig", Args: args}); d.Allowed {
			t.Errorf("Authorize(dig %v) allowed an out-of-scope or unverifiable resolver", args)
		}
	}
	for _, args := range [][]string{
		{"@10.0.0.5", "x"},
		{"x", "@corp.example"},
		{"@10.0.0.5", "corp.example"},
		{"@10.0.0.5", "+short", "mx", "corp.example"},
		{"corp.example", "@10.0.0.5", "-t", "any"},
	} {
		if d := g.Authorize(context.Background(), Command{Binary: "dig", Args: args}); !d.Allowed {
			t.Errorf("Authorize(dig %v) denied an in-scope resolver: %q", args, d.Reason)
		}
	}
}

// The queried name is data: with an in-scope resolver named, an out-of-scope
// name is allowed. Without an explicit resolver the name is still the only
// checkable target and stays scope-checked.
func TestDigQueryNameNotScopeCheckedWithExplicitServer(t *testing.T) {
	g := digGate(t, "dig")
	for _, args := range [][]string{
		{"@10.0.0.5", "anything.com"},
		{"anything.com", "@10.0.0.5"},
		{"@10.0.0.5", "-t", "mx", "anything.com"},
		{"@10.0.0.5", "-x", "8.8.8.8"},
		{"@10.0.0.5", "-q", "anything.com"},
		{"@corp.example", "anything.com", "txt"},
	} {
		if d := g.Authorize(context.Background(), Command{Binary: "dig", Args: args}); !d.Allowed {
			t.Errorf("Authorize(dig %v) denied a benign query name: %q", args, d.Reason)
		}
	}
	for _, args := range [][]string{
		{"anything.com"},
		{"8.8.8.8"},
		{"+short", "anything.com"},
	} {
		if d := g.Authorize(context.Background(), Command{Binary: "dig", Args: args}); d.Allowed {
			t.Errorf("Authorize(dig %v) allowed an out-of-scope name with no explicit resolver", args)
		}
	}
	if d := g.Authorize(context.Background(), Command{Binary: "dig", Args: []string{"corp.example"}}); !d.Allowed {
		t.Errorf("dig with an in-scope name and no @server must stay allowed: %q", d.Reason)
	}
}

func TestDigServerExtraction(t *testing.T) {
	got, ok := ExtractTargets(Command{Binary: "dig", Args: []string{"@8.8.8.8", "anything.com"}})
	if !ok || !reflect.DeepEqual(got, []string{"8.8.8.8"}) {
		t.Errorf("ExtractTargets(dig @8.8.8.8 anything.com) = %v, %v; want [8.8.8.8] true", got, ok)
	}
	// The query-name rule is bound to dig: another binary keeps every token.
	got, ok = ExtractTargets(Command{Binary: "host", Args: []string{"@8.8.8.8", "anything.com"}})
	if !ok || !reflect.DeepEqual(got, []string{"8.8.8.8", "anything.com"}) {
		t.Errorf("ExtractTargets(host ...) = %v, %v; want both tokens", got, ok)
	}
}

// An '@' in a non-dig tool's data or URL must keep its old meaning: the change
// is bound to dig and must not touch other tools.
func TestNonDigAtTokenUnaffected(t *testing.T) {
	g := digGate(t, "dig", "curl")
	for _, c := range []Command{
		{Binary: "curl", Args: []string{"-d", "user@corp.example", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"http://user@10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-d", "user@corp.example", "http://corp.example/x"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied an in-scope command with an @ token: %q", c.Binary, c.Args, d.Reason)
		}
	}
	// Existing behavior kept: an out-of-scope host in an email-like value is still seen.
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"-d", "user@evil.com", "http://10.0.0.5/"}}); d.Allowed {
		t.Error("curl with an out-of-scope user@host value must still be denied")
	}
}
