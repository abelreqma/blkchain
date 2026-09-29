package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildFilters(t *testing.T) {
	t.Run("empty is nil", func(t *testing.T) {
		m, err := buildFilters(nil, "", nil)
		if err != nil || m != nil {
			t.Fatalf("want nil,nil got %v,%v", m, err)
		}
	})
	t.Run("source and type", func(t *testing.T) {
		m, err := buildFilters(multiFlag{"vault"}, "payload", nil)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]interface{}{"source": "vault", "type": "payload"}
		if !reflect.DeepEqual(m, want) {
			t.Fatalf("got %v want %v", m, want)
		}
	})
	t.Run("key=value filters", func(t *testing.T) {
		m, err := buildFilters(nil, "", multiFlag{"section=intro", "lang=go"})
		if err != nil {
			t.Fatal(err)
		}
		if m["section"] != "intro" || m["lang"] != "go" {
			t.Fatalf("got %v", m)
		}
	})
	t.Run("bad filter errors", func(t *testing.T) {
		if _, err := buildFilters(nil, "", multiFlag{"nokey"}); err == nil {
			t.Fatal("want error for filter without =")
		}
		if _, err := buildFilters(nil, "", multiFlag{"=val"}); err == nil {
			t.Fatal("want error for empty key")
		}
	})
}

func TestHermesMCPStatus(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("present and enabled", func(t *testing.T) {
		p := write(t, `model:
  default: x
mcp_servers:
  zap:
    url: https://x
    enabled: true
  blkchain:
    command: /path/start_mcp.sh
    enabled: true
providers:
  omlx:
    name: oMLX
`)
		present, enabled, _, err := hermesMCPStatus(p, "blkchain")
		if err != nil || !present || !enabled {
			t.Fatalf("present=%v enabled=%v err=%v", present, enabled, err)
		}
	})

	t.Run("present but disabled", func(t *testing.T) {
		p := write(t, `mcp_servers:
  blkchain:
    command: /path
    enabled: false
`)
		present, enabled, _, _ := hermesMCPStatus(p, "blkchain")
		if !present || enabled {
			t.Fatalf("want present && !enabled, got present=%v enabled=%v", present, enabled)
		}
	})

	t.Run("present defaults to enabled", func(t *testing.T) {
		p := write(t, `mcp_servers:
  blkchain:
    command: /path
`)
		present, enabled, _, _ := hermesMCPStatus(p, "blkchain")
		if !present || !enabled {
			t.Fatalf("want present && enabled-by-default, got present=%v enabled=%v", present, enabled)
		}
	})

	t.Run("absent", func(t *testing.T) {
		p := write(t, `mcp_servers:
  zap:
    enabled: true
`)
		present, _, _, _ := hermesMCPStatus(p, "blkchain")
		if present {
			t.Fatal("want absent")
		}
	})

	t.Run("retired python server", func(t *testing.T) {
		for _, body := range []string{
			"mcp_servers:\n  blkchain:\n    command: /repo/.venv/bin/python\n    args: [\"-m\", \"blkchain.mcp_server\"]\n",
			"mcp_servers:\n  blkchain:\n    command: python\n    args:\n      - -m\n      - blkchain.mcp_server\n  other:\n    command: blk\n",
			"mcp_servers:\n  blkchain:\n    command: /path/start_mcp.sh\n",
		} {
			if _, _, python, _ := hermesMCPStatus(write(t, body), "blkchain"); !python {
				t.Errorf("not flagged as the retired Python server:\n%s", body)
			}
		}
		p := write(t, "mcp_servers:\n  blkchain:\n    command: blk\n    args: [mcp]\n  other:\n    args: [\"-m\", \"blkchain.mcp_server\"]\n")
		if _, _, python, _ := hermesMCPStatus(p, "blkchain"); python {
			t.Error("blk mcp flagged as the Python server")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if _, _, _, err := hermesMCPStatus(filepath.Join(t.TempDir(), "nope.yaml"), "blkchain"); err == nil {
			t.Fatal("want error for missing file")
		}
	})

	// The read is capped at 1 MiB: a larger file, directly or through a
	// symlink, is refused rather than read whole, and so is a path that is not
	// a regular file.
	t.Run("oversize and non-regular paths are refused", func(t *testing.T) {
		big := write(t, "mcp_servers:\n  blkchain:\n    command: blk\n# "+strings.Repeat("x", hermesConfigMaxBytes)+"\n")
		if present, _, _, err := hermesMCPStatus(big, "blkchain"); err == nil || present {
			t.Errorf("a file over the cap: present=%v err=%v, want an error", present, err)
		}
		huge := filepath.Join(t.TempDir(), "huge")
		f, err := os.Create(huge)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(64 << 20); err != nil { // sparse: large, but no disk use
			t.Fatal(err)
		}
		f.Close()
		link := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.Symlink(huge, link); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := hermesMCPStatus(link, "blkchain"); err == nil {
			t.Error("a symlink to a large source: want an error")
		}
		if _, _, _, err := hermesMCPStatus(t.TempDir(), "blkchain"); err == nil {
			t.Error("a directory: want an error")
		}
	})
}

func TestLastLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(p, []byte("a\nb\nc\nd\ne\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := lastLines(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"d", "e"}) {
		t.Fatalf("got %v", got)
	}
	got, _ = lastLines(p, 100)
	if len(got) != 5 {
		t.Fatalf("want all 5, got %d", len(got))
	}
	if got, _ := lastLines(p, 0); got != nil {
		t.Fatalf("want nil for n=0, got %v", got)
	}
}

func TestSplitFirst(t *testing.T) {
	cases := []struct{ in, wantF, wantR string }{
		{"ask how are you", "ask", "how are you"},
		{"search", "search", ""},
		{"  open  2  ", "open", "2"},
		{"", "", ""},
	}
	for _, c := range cases {
		f, r := splitFirst(c.in)
		if f != c.wantF || r != c.wantR {
			t.Errorf("splitFirst(%q) = %q,%q want %q,%q", c.in, f, r, c.wantF, c.wantR)
		}
	}
}

func TestMultiFlag(t *testing.T) {
	var m multiFlag
	_ = m.Set("a")
	_ = m.Set("b")
	if m.String() != "a,b" {
		t.Fatalf("got %q", m.String())
	}
	if len(m) != 2 {
		t.Fatalf("len %d", len(m))
	}
}

func TestVersionInfo(t *testing.T) {
	v, _, _, gover := versionInfo()
	if v == "" {
		t.Fatal("version should never be empty")
	}
	if gover == "" {
		t.Fatal("go version should be reported")
	}
}
