package main

import (
	"os"

	"blkchain/cli/internal/secgate"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/cursor"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func typeDraft(m model, text string) model {
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true})
	return nm.(model)
}

func TestDraftGrowsForSoftWrapAndResize(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m = typeDraft(m, strings.Repeat("wrapped text ", 12))
	if m.ta.Height() < 2 {
		t.Fatalf("soft wrap has height %d", m.ta.Height())
	}
	before := m.ta.Height()
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	m = nm.(model)
	if m.ta.Height() <= before {
		t.Fatalf("resize did not grow the draft: %d to %d", before, m.ta.Height())
	}
}

func TestWrappedDraftArrowsPreserveText(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.history = []string{"old question"}
	m.histIdx = 1
	m = typeDraft(m, strings.Repeat("wrapped text ", 12))
	draft := m.ta.Value()
	for _, k := range []tea.KeyType{tea.KeyUp, tea.KeyDown} {
		nm, _ := m.Update(tea.KeyMsg{Type: k})
		m = nm.(model)
		if m.ta.Value() != draft {
			t.Fatalf("arrow changed draft to %q", m.ta.Value())
		}
	}
}

func TestDraftReceivesCursorMessages(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	_, cmd := m.Update(cursor.Blink())
	if cmd == nil {
		t.Fatal("initial cursor message was dropped")
	}
}

func TestDraftByteLimitIncludesCombiningMarks(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m = typeDraft(m, "e"+strings.Repeat("\u0301", inputCharLimit))
	if len(m.ta.Value()) > inputCharLimit || !utf8.ValidString(m.ta.Value()) {
		t.Fatalf("draft has %d bytes, valid UTF-8 %v", len(m.ta.Value()), utf8.ValidString(m.ta.Value()))
	}
	if m.limitNotice() == "" {
		t.Fatal("truncated combining input has no notice")
	}
}

func TestDraftDeletesWholeGraphemes(t *testing.T) {
	useDeadServices(t)
	for _, cluster := range []string{"e\u0301", "\U0001f44d\U0001f3fd", "\U0001f1fa\U0001f1f8", "\U0001f469\u200d\U0001f4bb"} {
		m := frameModel(t)
		m = typeDraft(m, "a"+cluster)
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		if got := nm.(model).ta.Value(); got != "a" {
			t.Errorf("backspace %q left %q", cluster, got)
		}
	}
}

func TestEllipsizePreservesGraphemes(t *testing.T) {
	cluster := "\U0001f469\u200d\U0001f4bb"
	got := ellipsize(cluster+"abcdef", 5)
	if got != cluster+"..." || lipgloss.Width(got) > 5 {
		t.Fatalf("ellipsize returned %q (%d columns)", got, lipgloss.Width(got))
	}
}

func TestMarkdownEmojiShortcodes(t *testing.T) {
	old := useUnicode
	useUnicode = true
	t.Cleanup(func() { useUnicode = old })
	got := glowRender("Ready :thumbsup: :-)\n\n`literal :thumbsup:`\n\n```text\nfenced :thumbsup:\n```", 80)
	if !strings.Contains(got, "\U0001f44d") || !strings.Contains(stripANSI(got), "literal :thumbsup:") || !strings.Contains(stripANSI(got), "fenced :thumbsup:") || !strings.Contains(got, ":-)") {
		t.Fatalf("emoji or literal code missing: %q", got)
	}
}

func TestDraftKeepsEmojiTogetherAtWrapBoundary(t *testing.T) {
	useDeadServices(t)
	for _, cluster := range []string{"e\u0301", "\U0001f44d\U0001f3fd", "\U0001f469\u200d\U0001f4bb"} {
		for padding := 0; padding < 25; padding++ {
			m := frameModel(t)
			m.ta.SetWidth(20)
			m.setDraft(strings.Repeat("a", padding) + cluster + "end")
			if view := stripANSI(m.draftView()); !strings.Contains(view, cluster) {
				t.Fatalf("wrap split %q with %d preceding columns: %q", cluster, padding, view)
			}
		}
	}
}

func BenchmarkDraftTyping(b *testing.B) {
	useDeadServices(b)
	for _, tc := range []struct{ name, text string }{
		{"question", strings.Repeat("wrapped question ", 20)},
		{"large paste", strings.Repeat("a", inputCharLimit-1)},
		{"combining", "e" + strings.Repeat("\u0301", 4000)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			m := frameModel(b)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.ta.Reset()
				m = typeDraft(m, tc.text)
				_ = m.draftView()
			}
		})
	}
}

func TestClipboardPasteReachesDraftWithoutSubmitting(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	old := readDraftClipboard
	readDraftClipboard = func() (string, error) { return "/engage\n\U0001f469\u200d\U0001f4bb", nil }
	t.Cleanup(func() { readDraftClipboard = old })
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlV})
	if cmd == nil {
		t.Fatal("paste returned no clipboard command")
	}
	nm, _ = nm.(model).Update(cmd())
	m = nm.(model)
	if m.ta.Value() != "/engage\n\U0001f469\u200d\U0001f4bb" || m.working || m.overlay != nil || m.ta.Height() != 2 {
		t.Fatalf("paste did not remain an editable draft: %q", m.ta.Value())
	}
}

func TestBracketedPasteDoesNotOpenControls(t *testing.T) {
	useDeadServices(t)
	for _, text := range []string{"?", "@", "/engage\nnext line"} {
		m := typeDraft(frameModel(t), text)
		if m.ta.Value() != text || m.keyPanel || m.overlay != nil || m.working {
			t.Fatalf("pasted %q triggered a control", text)
		}
	}
}

func TestDraftAllEntryPathsEnforceLimit(t *testing.T) {
	useDeadServices(t)
	large := strings.Repeat("\U0001f44d\U0001f3fd", inputCharLimit)
	for _, path := range []string{"paste", "history", "editor"} {
		t.Run(path, func(t *testing.T) {
			m := frameModel(t)
			switch path {
			case "paste":
				nm, _ := m.Update(draftPasteMsg{text: large})
				m = nm.(model)
			case "history":
				m.history, m.histIdx = []string{large}, 1
				m = m.recallPrev()
			case "editor":
				p := t.TempDir() + "/draft.md"
				if err := os.WriteFile(p, []byte(large), 0o600); err != nil {
					t.Fatal(err)
				}
				nm, _ := m.applyEditorResult(editorDoneMsg{path: p})
				m = nm.(model)
			}
			if len(m.ta.Value()) > inputCharLimit || !utf8.ValidString(m.ta.Value()) || m.limitNotice() == "" {
				t.Fatalf("%s exceeded limit or lost its notice (%d bytes)", path, len(m.ta.Value()))
			}
		})
	}
}

func TestDraftLineLimitDoesNotSilentlyDrop(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.setDraft(strings.Repeat("\n", maxDraftLines-2))
	nm, _ := m.Update(draftPasteMsg{text: "a\nb\nc"})
	m = nm.(model)
	if m.ta.LineCount() != maxDraftLines || !m.draftTruncated || !strings.HasSuffix(m.ta.Value(), "a\nb") {
		t.Fatalf("line limit silently dropped content: %d lines, notice %v", m.ta.LineCount(), m.draftTruncated)
	}
}

func TestDraftGraphemeNavigationDeleteAndTranspose(t *testing.T) {
	useDeadServices(t)
	cluster := "\U0001f469\u200d\U0001f4bb"
	m := frameModel(t)
	m.setDraft("first line\na" + cluster + "b")
	for _, k := range []tea.KeyType{tea.KeyLeft, tea.KeyLeft} {
		nm, _ := m.Update(tea.KeyMsg{Type: k})
		m = nm.(model)
	}
	_, col := m.draftPosition()
	if col != 1 {
		t.Fatalf("left landed inside emoji at rune %d", col)
	}
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyDelete})
	m = nm.(model)
	if m.ta.Value() != "first line\nab" {
		t.Fatalf("delete split an emoji: %q", m.ta.Value())
	}
	m.setDraft("a" + cluster)
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlT})
	if got := nm.(model).ta.Value(); got != cluster+"a" {
		t.Fatalf("transpose split an emoji: %q", got)
	}
}

func TestDraftVerticalNavigationKeepsGraphemeBoundary(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.ta.SetWidth(20)
	m.setDraft(strings.Repeat("\U0001f469\u200d\U0001f4bb", 15))
	for i := 0; i < 6; i++ {
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
		m = nm.(model)
		_, col := m.draftPosition()
		if col%3 != 0 {
			t.Fatalf("up landed inside a joined emoji at rune %d", col)
		}
	}
}

func TestMarkdownASCIIKeepsEmojiShortcodes(t *testing.T) {
	old := useUnicode
	useUnicode = false
	t.Cleanup(func() { useUnicode = old })
	if got := glowRender("Ready :thumbsup:", 80); !strings.Contains(got, ":thumbsup:") || strings.Contains(got, "\U0001f44d") {
		t.Fatalf("ASCII mode transformed shortcode: %q", got)
	}
}

func TestDraftVerticalMovementPreservesPreferredColumn(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.setDraft("abcdefgh\nx\nabcdefgh")
	for range 2 {
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
		m = nm.(model)
	}
	line, col := m.draftPosition()
	if line != 0 || col != 8 {
		t.Fatalf("vertical movement lost preferred column: line %d, col %d", line, col)
	}
}

func TestDraftViewsFitWidthsAndKeepWrappedWords(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	text := strings.Repeat("word \U0001f469\u200d\U0001f4bb e\u0301 \u4e2d\u6587 ", 10)
	for width := 20; width <= 120; width++ {
		nm, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 24})
		m = nm.(model)
		m.setDraft(text)
		for _, row := range strings.Split(m.draftView(), "\n") {
			if lipgloss.Width(row) > width {
				t.Fatalf("draft at width %d has %d columns: %q", width, lipgloss.Width(row), row)
			}
		}
	}
	rows := wrapDraft("hello world", 8)
	if len(rows) != 2 || rows[0].text != "hello " || rows[1].text != "world" {
		t.Fatalf("word wrap: %+v", rows)
	}
}

func TestDraftScrollingKeepsViewportUntilCursorLeaves(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.setDraft("0\n1\n2\n3\n4\n5\n6\n7")
	before := m.draftTop
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = nm.(model)
	if m.draftTop != before {
		t.Fatalf("viewport jumped despite cursor remaining visible: %d to %d", before, m.draftTop)
	}
}

func TestReverseSearchAcceptanceUsesDraftBounds(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.rsearch = reverseSearch{open: true, match: strings.Repeat("\U0001f469\u200d\U0001f4bb", inputCharLimit)}
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(model)
	if m.rsearch.open || len(m.ta.Value()) > inputCharLimit || m.limitNotice() == "" || m.ta.Height() != 6 {
		t.Fatalf("reverse search acceptance bypassed draft bounds: %d bytes", len(m.ta.Value()))
	}
}

func TestOverlayCursorMessagesReachFocusedInputs(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	p := newClarifyPicker(Clarification{AllowCustom: true}, 80, nil)
	p.typing = true
	p.input.Focus()
	m.overlay = p
	if _, cmd := m.Update(cursor.Blink()); cmd == nil {
		t.Fatal("clarification cursor message was dropped")
	}
	confirm := newConfirmPicker(secgate.Command{}, 80, nil)
	confirm.editing = true
	confirm.input.Focus()
	m.overlay = confirm
	if _, cmd := m.Update(cursor.Blink()); cmd == nil {
		t.Fatal("confirmation cursor message was dropped")
	}
}

func TestDraftLayoutCacheRefreshesAfterResizeAndPaste(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.setDraft(strings.Repeat("word ", 30))
	before := m.draftLayout.rows
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	m = nm.(model)
	if len(m.draftLayout.rows) <= len(before) || m.draftLayout.width != m.ta.Width() {
		t.Fatal("resize retained stale wrapped rows")
	}
	nm, _ = m.Update(draftPasteMsg{text: "tail"})
	m = nm.(model)
	if m.draftLayout.value != m.ta.Value() || !strings.Contains(m.draftView(), "tail") {
		t.Fatal("paste retained stale wrapped rows")
	}
}
