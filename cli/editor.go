package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
)

// editor.go is the $EDITOR handoff (V2-BRIEF.md T5): Ctrl-G (or /editor) writes
// the current draft to a temp .md, suspends the TUI via tea.ExecProcess, runs the
// operator's editor, then reads the file back into the input. It never auto-submits.

// editorDoneMsg is sent when the external editor exits: path is the temp file to
// read back and delete, before is the draft as it was handed off (to detect an
// unchanged edit), err is the editor's exit error.
type editorDoneMsg struct {
	path   string
	before string
	err    error
}

// editorArgv resolves the editor command as an argv (never a shell string):
// $VISUAL, then $EDITOR, then vi. A value like "code --wait" is split into
// argv on spaces, so no shell interpretation happens.
func editorArgv() []string {
	for _, env := range []string{"VISUAL", "EDITOR"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			if fields := strings.Fields(v); len(fields) > 0 {
				return fields
			}
		}
	}
	return []string{"vi"}
}

// editorCmd writes the current draft to a temp .md and returns the tea.Cmd that
// suspends the TUI, runs the editor on it, and yields an editorDoneMsg. On a temp
// file error it returns a command that prints the error instead.
func (m model) editorCmd() tea.Cmd {
	draft := m.ta.Value()
	f, err := os.CreateTemp("", "blk-draft-*.md")
	if err != nil {
		return tea.Println(styleErr(fmt.Errorf("editor: %w", err)))
	}
	path := f.Name()
	if _, werr := f.WriteString(draft); werr != nil {
		f.Close()
		_ = os.Remove(path)
		return tea.Println(styleErr(fmt.Errorf("editor: %w", werr)))
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return tea.Println(styleErr(fmt.Errorf("editor: %w", cerr)))
	}

	argv := editorArgv()
	c := exec.Command(argv[0], append(argv[1:], path)...) //nolint:gosec // argv from env, no shell
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return editorDoneMsg{path: path, before: draft, err: err}
	})
}

// applyEditorResult reads the temp file back, deletes it, and loads the edited
// text into the input. An unchanged, empty, or errored edit keeps the draft and
// notes "edit cancelled". It never submits.
func (m model) applyEditorResult(msg editorDoneMsg) (tea.Model, tea.Cmd) {
	var loaded string
	var readErr error
	if msg.err == nil {
		b, e := os.ReadFile(msg.path)
		readErr, loaded = e, string(b)
	}
	if msg.path != "" {
		_ = os.Remove(msg.path)
	}

	if msg.err != nil || readErr != nil {
		return m, tea.Println("   " + Meta.Render("edit cancelled"))
	}
	edited := strings.TrimRight(loaded, "\n")
	if strings.TrimSpace(edited) == "" || edited == strings.TrimRight(msg.before, "\n") {
		return m, tea.Println("   " + Meta.Render("edit cancelled"))
	}
	m.ta.SetValue(edited)
	m.ta.SetHeight(clamp(m.ta.LineCount(), 1, 6))
	m.ta.CursorEnd()
	m = m.refreshPalette()
	return m, textarea.Blink
}
