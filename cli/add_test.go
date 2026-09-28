package main

import (
	"strings"
	"testing"
)

func TestParseAddArgsBasic(t *testing.T) {
	a, err := parseAddArgs([]string{"./notes.md"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a.path != "./notes.md" || a.source != "" || a.typ != "" {
		t.Errorf("parseAddArgs() = %+v, want path=./notes.md source= typ=", a)
	}
}

func TestParseAddArgsFlagsBeforeAndAfterPath(t *testing.T) {
	a, err := parseAddArgs([]string{"--source", "mydocs", "--type", "md", "./notes.md"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a.path != "./notes.md" || a.source != "mydocs" || a.typ != "md" {
		t.Errorf("parseAddArgs() = %+v, want path=./notes.md source=mydocs typ=md", a)
	}

	// Flags after the positional path must also work (reorder handles this,
	// same as search/ask).
	a2, err := parseAddArgs([]string{"./notes.md", "--source", "mydocs", "--type", "md"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a2 != a {
		t.Errorf("parseAddArgs() with trailing flags = %+v, want %+v", a2, a)
	}
}

func TestParseAddArgsRejectsUnknownType(t *testing.T) {
	_, err := parseAddArgs([]string{"--type", "exe", "./notes.md"})
	if err == nil {
		t.Fatal("expected error for unknown --type, got nil")
	}
	if !strings.Contains(err.Error(), "md, txt, or pdf") {
		t.Errorf("error = %v, want message naming the allowed types", err)
	}
}

func TestParseAddArgsAcceptsEachKnownType(t *testing.T) {
	for typ := range addTypeMap {
		a, err := parseAddArgs([]string{"--type", typ, "path"})
		if err != nil {
			t.Fatalf("parseAddArgs(--type %s) error = %v", typ, err)
		}
		if a.typ != typ {
			t.Errorf("parseAddArgs(--type %s).typ = %q", typ, a.typ)
		}
	}
}

func TestParseAddArgsRequiresExactlyOnePath(t *testing.T) {
	if _, err := parseAddArgs(nil); err == nil {
		t.Error("expected error for missing path, got nil")
	}
	if _, err := parseAddArgs([]string{"a", "b"}); err == nil {
		t.Error("expected error for two positional args, got nil")
	}
}

func TestParseAddArgsAcceptsURL(t *testing.T) {
	a, err := parseAddArgs([]string{"https://example.com/doc"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a.path != "https://example.com/doc" {
		t.Errorf("parseAddArgs().path = %q", a.path)
	}
}

func TestLastNonEmptyLine(t *testing.T) {
	got, err := lastNonEmptyLine(strings.NewReader("line one\n\n{\"indexed\":1}\n\n"))
	if err != nil {
		t.Fatalf("lastNonEmptyLine() error = %v", err)
	}
	if got != `{"indexed":1}` {
		t.Errorf("lastNonEmptyLine() = %q", got)
	}
}

func TestIsConnectionRefused(t *testing.T) {
	cases := map[string]bool{
		"requests.exceptions.ConnectionError: HTTPConnectionPool":             true,
		"Failed to establish a new connection: [Errno 61] Connection refused": true,
		"Max retries exceeded with url: /embed":                               true,
		"error: no such file or directory: /tmp/nope.md":                      false,
		"": false,
	}
	for s, want := range cases {
		if got := isConnectionRefused(s); got != want {
			t.Errorf("isConnectionRefused(%q) = %v, want %v", s, got, want)
		}
	}
}
