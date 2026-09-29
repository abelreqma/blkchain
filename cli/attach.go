package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

// attach.go is the @file attach + /init ambient-context features (V2-BRIEF.md
// T5). @ (or /attach) opens a file picker overlay that injects a file's bounded
// text into the NEXT prompt; /init loads ./.blk/context.md as ambient session
// context. All file reads are zero-trust: size-bounded and read as text only.

const (
	// maxAttachBytes bounds an @file attachment so a huge file can't blow up the
	// prompt (resource-limits / zero-trust).
	maxAttachBytes = 64 << 10 // 64 KiB
	// maxInitBytes bounds the /init ambient context file.
	maxInitBytes = 128 << 10 // 128 KiB
	// maxDirEntries bounds how many entries the file picker lists per directory.
	maxDirEntries = 500
	// initContextPath is the per-project ambient context file (relative to cwd).
	initContextPath = ".blk/context.md"
)

// attachment is one file queued for the next prompt.
type attachment struct {
	path    string
	content string
}

// fileSelectedMsg is emitted by the file picker when the operator selects a file.
type fileSelectedMsg struct{ path string }

// readAttachment reads path as bounded text for prompt injection. It refuses
// directories and files over maxAttachBytes (zero-trust: bound size, read as
// text, never execute).
func readAttachment(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("%s is a directory", filepath.Base(path))
	}
	if fi.Size() > maxAttachBytes {
		return "", fmt.Errorf("file too large (%d bytes; cap %d)", fi.Size(), maxAttachBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// loadInitContext reads ./.blk/context.md (bounded) as ambient context, returning
// (content, true) when present and non-empty.
func loadInitContext() (string, bool) {
	fi, err := os.Stat(initContextPath)
	if err != nil || fi.IsDir() {
		return "", false
	}
	f, err := os.Open(initContextPath)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxInitBytes))
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", false
	}
	return s, true
}

// buildContextPreface assembles the ambient context + any pending attachments
// into a text preface for the next prompt. Empty when there is nothing to inject.
func (m model) buildContextPreface() string {
	var b strings.Builder
	if strings.TrimSpace(m.ambient) != "" {
		b.WriteString("Project context (.blk/context.md):\n")
		b.WriteString(m.ambient)
		b.WriteString("\n\n")
	}
	for _, a := range m.attachments {
		fmt.Fprintf(&b, "Attached file %s:\n%s\n\n", filepath.Base(a.path), a.content)
	}
	return strings.TrimSpace(b.String())
}

// openFilePicker opens the file picker overlay rooted at the working directory.
func (m model) openFilePicker() (tea.Model, tea.Cmd) {
	dir, err := os.Getwd()
	if err != nil || dir == "" {
		dir = "."
	}
	m.pal.open = false
	m.overlay = newFilePicker(dir, m.width)
	return m, nil
}

// --- file picker overlay ---

// fileEntry is one row in the file picker; ".." is the parent directory.
type fileEntry struct {
	name  string
	isDir bool
	path  string
}

func (e fileEntry) FilterValue() string { return e.name }

type filePicker struct {
	dir   string
	all   []fileEntry
	list  list.Model
	query string
	width int
}

// newFilePicker builds the picker for dir.
func newFilePicker(dir string, width int) filePicker {
	p := filePicker{dir: dir, width: width}
	p.all = readDirEntries(dir)
	items := fileItems(p.all, "")
	w := clampWidth(width-6, 30, 72)
	p.list = newCompactList(items, w, clampHeight(len(items), 10), fileRow)
	return p
}

// readDirEntries lists dir with ".." first, then directories, then files, each
// alphabetical, bounded to maxDirEntries.
func readDirEntries(dir string) []fileEntry {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	out := []fileEntry{}
	if parent := filepath.Dir(abs); parent != abs {
		out = append(out, fileEntry{name: "..", isDir: true, path: parent})
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		return out
	}
	var dirs, files []fileEntry
	for _, d := range des {
		e := fileEntry{name: d.Name(), isDir: d.IsDir(), path: filepath.Join(abs, d.Name())}
		if d.IsDir() {
			dirs = append(dirs, e)
		} else {
			files = append(files, e)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].name < dirs[j].name })
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	out = append(out, dirs...)
	out = append(out, files...)
	if len(out) > maxDirEntries {
		out = out[:maxDirEntries]
	}
	return out
}

// fileItems filters entries by a case-insensitive substring query (".." always
// shown so the operator can navigate up).
func fileItems(all []fileEntry, query string) []list.Item {
	q := strings.ToLower(strings.TrimSpace(query))
	var items []list.Item
	for _, e := range all {
		if e.name == ".." || q == "" || strings.Contains(strings.ToLower(e.name), q) {
			items = append(items, e)
		}
	}
	return items
}

// refilter rebuilds the visible list from the current query.
func (p filePicker) refilter() filePicker {
	items := fileItems(p.all, p.query)
	p.list.SetItems(items)
	p.list.SetHeight(clampHeight(len(items), 10))
	p.list.Select(0)
	return p
}

func fileRow(selected bool, item list.Item) string {
	e := item.(fileEntry)
	name := sanitizeTerminal(e.name)
	if e.isDir && e.name != ".." {
		name += "/"
	}
	if selected {
		return Prompt.Render(Glyph(GlyphPrompt)) + " " + Key.Render(name)
	}
	return "  " + Body.Render(name)
}

func (p filePicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		p.list, cmd = p.list.Update(msg)
		return p, cmd
	}
	switch km.String() {
	case "esc":
		return p, closeOverlayCmd
	case "enter":
		e, ok := p.list.SelectedItem().(fileEntry)
		if !ok {
			return p, nil
		}
		if e.isDir {
			p.dir = e.path
			p.all = readDirEntries(p.dir)
			p.query = ""
			return p.refilter(), nil
		}
		path := e.path
		return p, func() tea.Msg { return fileSelectedMsg{path: path} }
	case "backspace":
		if p.query != "" {
			r := []rune(p.query)
			p.query = string(r[:len(r)-1])
			return p.refilter(), nil
		}
		parent := filepath.Dir(p.dir)
		if parent != p.dir {
			p.dir = parent
			p.all = readDirEntries(p.dir)
			return p.refilter(), nil
		}
		return p, nil
	case "up", "down":
		var cmd tea.Cmd
		p.list, cmd = p.list.Update(msg)
		return p, cmd
	default:
		if len(km.Runes) > 0 {
			p.query += string(km.Runes)
			return p.refilter(), nil
		}
		var cmd tea.Cmd
		p.list, cmd = p.list.Update(msg)
		return p, cmd
	}
}

func (p filePicker) View(width, height int) string {
	// The header (directory and filter) takes 2 rows; the list gets the rest and
	// is sized to the box on every render. The directory is untrusted (file
	// names), so it is sanitized and reduced to one line before it is cut to fit.
	body := func(w, rows int) string {
		dirW := w
		if p.query != "" {
			dirW = max(w-2-len([]rune(p.query)), 1)
		}
		header := Meta.Render(ellipsize(oneLine(sanitizeTerminal(p.dir)), dirW))
		if p.query != "" {
			header += "  " + Body.Render(p.query)
		}
		// Below 3 rows the blank spacer goes, then the header, so the list keeps a row.
		var parts []string
		if rows >= 2 {
			parts = append(parts, header)
		}
		if rows >= 3 {
			parts = append(parts, "")
		}
		if len(p.all) == 0 {
			return strings.Join(append(parts, Meta.Render("empty directory")), "\n")
		}
		p.list.SetSize(w, max(rows-len(parts), 1))
		return strings.Join(append(parts, p.list.View()), "\n")
	}
	return overlayBox(overlaySpec{
		title: "ATTACH FILE",
		wantW: 72, wantRows: 2 + clampHeight(len(p.list.Items()), 10), minRows: 5, body: body,
	}, width, height)
}
