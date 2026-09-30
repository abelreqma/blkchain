package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// runOpen opens a source file in a pager (or $EDITOR with --edit). The path may
// be absolute or relative to the project root, so a `Path` printed by
// `blk search` (e.g. sources/foo.md) can be opened verbatim.
func runOpen(args []string) error {
	var edit bool
	var section string
	fs := newFlagSet("open")
	defineOpenFlags(fs, &edit, &section)
	if err := parseFlags(fs, reorder(args, map[string]bool{"section": true})); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return missingArg("open", "missing file path", "open sources/notes/ssrf.md")
	}
	return openFile(fs.Arg(0), section, edit)
}

// defineOpenFlags declares `blk open`'s flags.
func defineOpenFlags(fs *flag.FlagSet, edit *bool, section *string) {
	fs.BoolVar(edit, "edit", false, "open in your editor ($EDITOR) instead of the pager")
	fs.StringVar(section, "section", "", "jump to this heading when the pager is less")
}

// openFile resolves path (absolute, or relative to CWD then project root) and
// opens it. An http(s) URL only prints the web notice. When edit is true it uses $EDITOR; otherwise $PAGER, falling back
// to less. The file path is passed as an argv element, never via a shell.
// When section is non-empty and the pager is less, less starts at the first
// match of the section heading; any other viewer opens at the top.
func openFile(path, section string, edit bool) error {
	// A web result is never launched or fetched: say so and show the URL, the
	// same answer the TUI /open gives.
	if isWebURL(path) {
		fmt.Println(openWebNotice(path))
		return nil
	}
	resolved, err := resolveSourcePath(path)
	if err != nil {
		return err
	}

	var viewer string
	if edit {
		viewer = firstNonEmpty(os.Getenv("EDITOR"), os.Getenv("VISUAL"), "vi")
	} else {
		viewer = firstNonEmpty(os.Getenv("PAGER"), "less")
	}

	bin, lookErr := exec.LookPath(viewer)
	if lookErr != nil {
		return fmt.Errorf("open: %q not found, set $%s", viewer, pagerOrEditor(edit))
	}
	// A CWD-relative path can start with "-" or "+" and would reach the viewer
	// as an option (less -oX, vi +cmd). An absolute path always starts with "/".
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if !edit && section != "" && filepath.Base(firstField(viewer)) == "less" {
		if pat := sectionPattern(section); pat != "" {
			return runViewer(bin, []string{"+/" + pat, "--", abs})
		}
	}
	return runViewer(bin, []string{abs})
}

// sectionPatternMax caps the heading text used for a pager search, in runes,
// before escaping.
const sectionPatternMax = 120

var pageSuffixRe = regexp.MustCompile(`\s*\(p\.\d+\)\s*$`)
var pdfPageRe = regexp.MustCompile(`(?i)^page \d+$`)

// sectionPattern turns a chunk section into a literal less search pattern for
// its most specific heading, or "" when there is nothing to search for. The
// ingester joins heading levels with " > " and writes "page N" or
// "WSTG-XXX-NN (p.N)" for PDFs. The section is untrusted payload text: control
// characters become spaces, the length is capped, and every regex
// metacharacter is neutralised so the heading matches literally under BRE, ERE
// and PCRE alike.
func sectionPattern(section string) string {
	segs := strings.Split(section, " > ")
	var head string
	for i := len(segs) - 1; i >= 0 && head == ""; i-- {
		head = cleanHeading(segs[i])
	}
	if head == "" || pdfPageRe.MatchString(head) {
		return ""
	}
	if utf8.RuneCountInString(head) > sectionPatternMax {
		head = strings.TrimSpace(string([]rune(head)[:sectionPatternMax]))
	}
	var b strings.Builder
	for i, r := range head {
		switch r {
		case '\\', '.', '*', '[', ']', '^', '$', '/':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '+', '?', '(', ')', '{', '}', '|':
			b.WriteString("[" + string(r) + "]")
		case '!', '@':
			// less reads these as search modifiers when they lead the pattern.
			if i == 0 {
				b.WriteString("[" + string(r) + "]")
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cleanHeading drops a leading "#" run and a trailing "(p.N)" page suffix,
// replaces control characters with spaces, and collapses whitespace.
func cleanHeading(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s), "#"))
	s = pageSuffixRe.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}

// firstField returns the first whitespace-separated token of s, so a pager
// setting such as "less -R" is recognised as less.
func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// runViewer runs the pager or editor on the terminal. It is a variable so tests
// can capture the argv.
var runViewer = func(bin string, args []string) error {
	c := exec.Command(bin, args...)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

// resolveSourcePath returns an existing file path for the given input, trying it
// as-is (absolute or CWD-relative), then relative to the project root, then
// relative to each configured corpus root (see corpusRoots).
func resolveSourcePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		if fileExists(path) {
			return path, nil
		}
		return "", fmt.Errorf("open: no such file: %s", path)
	}
	if fileExists(path) {
		return path, nil
	}
	if root, err := projectRoot(); err == nil {
		cand := filepath.Join(root, path)
		if fileExists(cand) {
			return cand, nil
		}
	}
	for _, root := range corpusRoots() {
		cand := filepath.Clean(filepath.Join(root, path))
		if !withinRoot(root, cand) {
			continue
		}
		if fileExists(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("open: no such file: %s", path)
}

// corpusRoots returns the configured corpus directories, in lookup order. A
// citation path is relative to one of these, not to the project root. Roots
// whose setting is empty are skipped.
func corpusRoots() []string {
	var roots []string
	for _, k := range []string{"BLKCHAIN_SOURCES_DIR", "BLKCHAIN_SKILLS_DIR", "BLKCHAIN_SECLISTS_DIR"} {
		if v := os.Getenv(k); v != "" {
			roots = append(roots, filepath.Clean(v))
		}
	}
	if v := os.Getenv("BLKCHAIN_WSTG_PDF"); v != "" {
		roots = append(roots, filepath.Dir(filepath.Clean(v)))
	}
	return roots
}

// withinRoot reports whether cand is root or lies beneath it. Both must be
// cleaned, so a ".." in the joined path cannot escape the root.
func withinRoot(root, cand string) bool {
	return cand == root || strings.HasPrefix(cand, root+string(os.PathSeparator))
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func pagerOrEditor(edit bool) string {
	if edit {
		return "EDITOR"
	}
	return "PAGER"
}
