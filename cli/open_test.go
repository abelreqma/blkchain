package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// captureViewer replaces runViewer for the test and returns a pointer to the
// argv the viewer would receive.
func captureViewer(t *testing.T) *[]string {
	t.Helper()
	var got []string
	orig := runViewer
	runViewer = func(bin string, args []string) error {
		got = args
		return nil
	}
	t.Cleanup(func() { runViewer = orig })
	return &got
}

func TestOpenFilePassesAbsolutePath(t *testing.T) {
	for _, name := range []string{"-oX", "+cmd", "plain.md"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			t.Setenv("PAGER", "sh")
			got := captureViewer(t)

			if err := openFile(name, "", false); err != nil {
				t.Fatalf("openFile(%q) error = %v", name, err)
			}
			if len(*got) != 1 || !filepath.IsAbs((*got)[0]) || !strings.HasSuffix((*got)[0], string(filepath.Separator)+name) {
				t.Errorf("viewer argv = %q, want one absolute path ending in %q", *got, name)
			}
			if strings.HasPrefix((*got)[0], "-") || strings.HasPrefix((*got)[0], "+") {
				t.Errorf("viewer argv %q can be parsed as an option", *got)
			}
		})
	}
}

// fakeLess puts an executable named less first on PATH and selects it as the
// pager, so the section jump path runs without a real less.
func fakeLess(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "less"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("PAGER", "less")
}

func TestSectionPattern(t *testing.T) {
	long := strings.Repeat("A", 500)
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"plain heading", "Testing for SQL Injection", "Testing for SQL Injection"},
		{"breadcrumb last segment", "SSRF > Cloud Metadata > IMDSv1", "IMDSv1"},
		{"hash run stripped", "## Blind SSRF", "Blind SSRF"},
		{"hash in breadcrumb segment", "Top > ### Deep", "Deep"},
		{"page suffix dropped", "WSTG-INFO-01 (p.12)", "WSTG-INFO-01"},
		{"pdf page only", "page 7", ""},
		{"page suffix only", "(p.3)", ""},
		{"hash only", "###", ""},
		{"regex metachars escaped", "a.b*c[d]^e$f\\g/h", `a\.b\*c\[d\]\^e\$f\\g\/h`},
		{"ere metachars bracketed", "f(x)+y?{1}|z", "f[(]x[)][+]y[?][{]1[}][|]z"},
		{"leading less modifier bracketed", "!x", "[!]x"},
		{"leading at bracketed", "@x", "[@]x"},
		{"leading star escaped", "*x", `\*x`},
		{"slash kept in heading", "SSRF / Cloud", `SSRF \/ Cloud`},
		{"control chars dropped", "Foo\x1b[31m\nbar\x07\x00\t baz", `Foo \[31m bar baz`},
		{"whitespace collapsed", "a   b", "a b"},
		{"trailing separator", "A > ", "A"},
		{"long heading capped", long, strings.Repeat("A", sectionPatternMax)},
		{"invalid utf8", "ab\xffcd", "abcd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sectionPattern(c.in); got != c.want {
				t.Errorf("sectionPattern(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSectionPatternHostileHasNoControlChars(t *testing.T) {
	hostile := "\x1b]0;pwn\x07\r\n\x00\x7f" + strings.Repeat(".*[]^$\\/!@", 200)
	got := sectionPattern(hostile)
	if len([]rune(got)) > sectionPatternMax*3 {
		t.Errorf("pattern not bounded: %d runes", len([]rune(got)))
	}
	for _, r := range got {
		if unicode.IsControl(r) {
			t.Fatalf("control char %U reached the pattern: %q", r, got)
		}
	}
}

func TestOpenFileSectionJumpsInLess(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(doc, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeLess(t)
	got := captureViewer(t)

	if err := openFile(doc, "Top > Blind SSRF.v2 (p.4)", false); err != nil {
		t.Fatal(err)
	}
	want := []string{`+/Blind SSRF\.v2`, "--", doc}
	if strings.Join(*got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", *got, want)
	}
}

func TestOpenFileSectionHostileIsOneSafeElement(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "-doc.md")
	if err := os.WriteFile(doc, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeLess(t)
	got := captureViewer(t)
	t.Chdir(dir)

	hostile := "\x1b[2J\n; rm -rf / `id` $(id) -- " + strings.Repeat("[", 5000)
	if err := openFile("-doc.md", hostile, false); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 3 || (*got)[1] != "--" || !filepath.IsAbs((*got)[2]) {
		t.Fatalf("argv shape = %q", *got)
	}
	jump := (*got)[0]
	if !strings.HasPrefix(jump, "+/") {
		t.Errorf("jump = %q", jump)
	}
	for _, r := range jump {
		if unicode.IsControl(r) {
			t.Fatalf("control char %U in jump", r)
		}
	}
	if len(jump) > sectionPatternMax*2+2 {
		t.Errorf("jump not bounded: %d bytes", len(jump))
	}
}

func TestOpenFileSectionIgnoredOutsideLess(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(doc, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Run("other pager", func(t *testing.T) {
		t.Setenv("PAGER", "sh")
		got := captureViewer(t)
		if err := openFile(doc, "Heading", false); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != doc {
			t.Errorf("argv = %q, want [%s]", *got, doc)
		}
	})
	t.Run("edit", func(t *testing.T) {
		fakeLess(t)
		t.Setenv("EDITOR", "less")
		got := captureViewer(t)
		if err := openFile(doc, "Heading", true); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != doc {
			t.Errorf("argv = %q, want [%s]", *got, doc)
		}
	})
	t.Run("less without section", func(t *testing.T) {
		fakeLess(t)
		got := captureViewer(t)
		if err := openFile(doc, "", false); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != doc {
			t.Errorf("argv = %q, want [%s]", *got, doc)
		}
	})
	t.Run("less with pdf page only", func(t *testing.T) {
		fakeLess(t)
		got := captureViewer(t)
		if err := openFile(doc, "page 9", false); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != doc {
			t.Errorf("argv = %q, want [%s]", *got, doc)
		}
	})
}

func TestOpenFileWebURLOnlyPrintsNotice(t *testing.T) {
	fakeLess(t)
	got := captureViewer(t)
	if err := openFile("https://example.com/p", "Heading", false); err != nil {
		t.Fatal(err)
	}
	if *got != nil {
		t.Errorf("viewer ran for a web URL: %q", *got)
	}
}

func TestRunOpenSectionFlag(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(doc, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeLess(t)
	got := captureViewer(t)
	for _, args := range [][]string{
		{doc, "--section", "Blind SSRF"},
		{"--section=Blind SSRF", doc},
	} {
		*got = nil
		if err := runOpen(args); err != nil {
			t.Fatal(err)
		}
		want := []string{"+/Blind SSRF", "--", doc}
		if strings.Join(*got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("runOpen(%q) argv = %q, want %q", args, *got, want)
		}
	}
	*got = nil
	if err := runOpen([]string{doc}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || (*got)[0] != doc {
		t.Errorf("no --section argv = %q", *got)
	}
}

func TestResolveSourcePath(t *testing.T) {
	for _, k := range []string{"BLKCHAIN_SOURCES_DIR", "BLKCHAIN_SKILLS_DIR", "BLKCHAIN_SECLISTS_DIR", "BLKCHAIN_WSTG_PDF"} {
		t.Setenv(k, "")
	}
	write := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Run from an empty directory so the CWD attempt never matches by accident.
	t.Chdir(t.TempDir())

	t.Run("sources root", func(t *testing.T) {
		root := t.TempDir()
		write(filepath.Join(root, "sub", "skill.md"))
		t.Setenv("BLKCHAIN_SOURCES_DIR", root)
		got, err := resolveSourcePath("sub/skill.md")
		if err != nil || got != filepath.Join(root, "sub", "skill.md") {
			t.Errorf("got %q, %v", got, err)
		}
	})

	t.Run("skills seclists and wstg dir roots", func(t *testing.T) {
		skills, seclists, wstg := t.TempDir(), t.TempDir(), t.TempDir()
		write(filepath.Join(skills, "a", "SKILL.md"))
		write(filepath.Join(seclists, "b.txt"))
		write(filepath.Join(wstg, "guide.md"))
		t.Setenv("BLKCHAIN_SKILLS_DIR", skills)
		t.Setenv("BLKCHAIN_SECLISTS_DIR", seclists)
		t.Setenv("BLKCHAIN_WSTG_PDF", filepath.Join(wstg, "wstg.pdf"))
		for path, want := range map[string]string{
			"a/SKILL.md": filepath.Join(skills, "a", "SKILL.md"),
			"b.txt":      filepath.Join(seclists, "b.txt"),
			"guide.md":   filepath.Join(wstg, "guide.md"),
		} {
			if got, err := resolveSourcePath(path); err != nil || got != want {
				t.Errorf("resolveSourcePath(%q) = %q, %v; want %q", path, got, err, want)
			}
		}
	})

	t.Run("dotdot escape rejected", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "root")
		write(filepath.Join(root, "in.md"))
		write(filepath.Join(parent, "escape.md"))
		t.Setenv("BLKCHAIN_SOURCES_DIR", root)
		if got, err := resolveSourcePath("../escape.md"); err == nil {
			t.Errorf("resolveSourcePath escaped the root, got %q", got)
		}
	})

	t.Run("absolute and cwd paths unchanged", func(t *testing.T) {
		dir := t.TempDir()
		write(filepath.Join(dir, "abs.md"))
		if got, err := resolveSourcePath(filepath.Join(dir, "abs.md")); err != nil || got != filepath.Join(dir, "abs.md") {
			t.Errorf("absolute: got %q, %v", got, err)
		}
		t.Chdir(dir)
		if got, err := resolveSourcePath("abs.md"); err != nil || got != "abs.md" {
			t.Errorf("cwd: got %q, %v", got, err)
		}
	})
}
