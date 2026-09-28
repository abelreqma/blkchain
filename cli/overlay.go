package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// overlay.go holds the focused overlay pickers (V2-BRIEF.md T4): the /resume
// session picker and the /model reasoning picker. An overlay captures keys while
// open; the base Update passes through only quit (tui.go). Each overlay renders
// over the live region, replacing the input area, inside one rounded single-line
// border in Rule with a Surface fill (per the design). Overlays never mutate the
// model directly; they emit result messages the base Update handles.

// overlayModel is the minimal contract the base loop drives: feed it a msg, get
// back the (possibly updated) overlay and a command; render it at a width.
type overlayModel interface {
	Update(tea.Msg) (overlayModel, tea.Cmd)
	View(width int) string
}

// --- overlay result messages (handled in the base Update) ---

type overlayCloseMsg struct{}              // Esc: cancel, keep current session/model
type resumeSelectedMsg struct{ id string } // open this session
type modelSelectedMsg struct{ model, reasoning string }

// openModelPickerMsg carries the discovered models into the model picker. Model
// discovery is a network call, so it runs in a command and opens the overlay on
// completion, keeping the event loop responsive and preserving the input draft.
type openModelPickerMsg struct {
	models    []string
	current   string
	reasoning string
}

// reasoningLevels are the reasoning-effort choices, low to high.
var reasoningLevels = []string{"minimal", "low", "medium", "high"}

// --- shared list plumbing ---

// rowDelegate is a compact single-line list delegate: it defers each row's
// rendering to render(selected, item), so the pickers control the selected
// styling (Heading bold + ❯ Accent) directly.
type rowDelegate struct {
	render func(selected bool, item list.Item) string
}

func (d rowDelegate) Height() int                         { return 1 }
func (d rowDelegate) Spacing() int                        { return 0 }
func (d rowDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (d rowDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	fmt.Fprint(w, d.render(index == m.Index(), item))
}

// newCompactList builds a list stripped of its title, status bar, help,
// pagination, and filtering — just a scrollable column of rows for an overlay.
func newCompactList(items []list.Item, width, height int, render func(bool, list.Item) string) list.Model {
	l := list.New(items, rowDelegate{render: render}, width, height)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	l.SetShowFilter(false)
	l.SetFilteringEnabled(false)
	l.DisableQuitKeybindings()
	return l
}

// strItem is a plain string list item (model ids, reasoning levels).
type strItem string

func (s strItem) FilterValue() string { return string(s) }

// strRow renders a plain string row with the selected marker/styling.
func strRow(selected bool, item list.Item) string {
	label := string(item.(strItem))
	if selected {
		return Prompt.Render(Glyph(GlyphPrompt)) + " " + Key.Render(label)
	}
	return "  " + Body.Render(label)
}

// overlayBox wraps content in the one rounded border + Surface fill the design
// prescribes, with a title heading and a muted footer keybar.
func overlayBox(title, body, footer string, width int) string {
	var b strings.Builder
	b.WriteString(H2.Render(title))
	b.WriteString("\n\n")
	b.WriteString(body)
	if footer != "" {
		b.WriteString("\n\n")
		b.WriteString(footer)
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(Rule).
		Background(Surface).
		Padding(0, 1)
	inner := width - 4
	if inner > 20 {
		box = box.MaxWidth(width)
	}
	return box.Render(b.String())
}

// clampHeight bounds a list's visible height to [1, cap].
func clampHeight(n, cap int) int {
	if n < 1 {
		return 1
	}
	if n > cap {
		return cap
	}
	return n
}

// relTime renders a compact "n ago" for a unix timestamp.
func relTime(ts int64) string {
	if ts == 0 {
		return "—"
	}
	d := time.Since(time.Unix(ts, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

// --- resume picker ---

// resumeItem is one session row; num is its 1-9 quick-pick key (0 = none).
type resumeItem struct {
	meta sessionMeta
	num  int
}

func (r resumeItem) FilterValue() string { return r.meta.Title }

type resumePicker struct {
	list    list.Model
	metas   []sessionMeta
	confirm bool // 'd' pressed, awaiting 'y'
}

// newResumePicker builds the picker from the current session list, selecting the
// current session if present.
func newResumePicker(metas []sessionMeta, currentID string, width int) resumePicker {
	items := resumeItems(metas)
	w := clampWidth(width-6, 30, 72)
	h := clampHeight(len(items), 9)
	l := newCompactList(items, w, h, resumeRow)
	for i, m := range metas {
		if m.ID == currentID {
			l.Select(i)
			break
		}
	}
	return resumePicker{list: l, metas: metas}
}

func resumeItems(metas []sessionMeta) []list.Item {
	items := make([]list.Item, len(metas))
	for i, m := range metas {
		num := 0
		if i < 9 {
			num = i + 1
		}
		items[i] = resumeItem{meta: m, num: num}
	}
	return items
}

func resumeRow(selected bool, item list.Item) string {
	r := item.(resumeItem)
	title := strings.TrimSpace(r.meta.Title)
	if title == "" {
		title = r.meta.ID
	}
	num := "  "
	if r.num > 0 {
		num = fmt.Sprintf("%d ", r.num)
	}
	meta := fmt.Sprintf("%d msgs · %s", r.meta.MsgCount, relTime(r.meta.UpdatedAt))
	if selected {
		return Prompt.Render(Glyph(GlyphPrompt)) + " " + Key.Render(num) + Key.Render(title) + "  " + Meta.Render(meta)
	}
	return "  " + Meta.Render(num) + Body.Render(title) + "  " + Meta.Render(meta)
}

func (p resumePicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		p.list, cmd = p.list.Update(msg)
		return p, cmd
	}
	s := km.String()

	if p.confirm {
		if s == "y" || s == "Y" {
			if it, ok := p.list.SelectedItem().(resumeItem); ok {
				_ = deleteSession(it.meta.ID)
			}
			p.confirm = false
			return p.reload(), nil
		}
		p.confirm = false // any other key cancels the delete
		return p, nil
	}

	switch s {
	case "esc":
		return p, closeOverlayCmd
	case "enter":
		if it, ok := p.list.SelectedItem().(resumeItem); ok {
			id := it.meta.ID
			return p, func() tea.Msg { return resumeSelectedMsg{id: id} }
		}
		return p, nil
	case "d":
		if len(p.metas) > 0 {
			p.confirm = true
		}
		return p, nil
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		n := int(s[0] - '0')
		if n >= 1 && n <= len(p.metas) {
			id := p.metas[n-1].ID
			return p, func() tea.Msg { return resumeSelectedMsg{id: id} }
		}
		return p, nil
	}

	var cmd tea.Cmd
	p.list, cmd = p.list.Update(msg)
	return p, cmd
}

// reload rebuilds the picker after a delete.
func (p resumePicker) reload() resumePicker {
	metas, _ := listSessions()
	p.metas = metas
	p.list.SetItems(resumeItems(metas))
	p.list.SetHeight(clampHeight(len(metas), 9))
	return p
}

func (p resumePicker) View(width int) string {
	body := p.list.View()
	if len(p.metas) == 0 {
		body = Meta.Render("no saved sessions yet")
	}
	footer := Meta.Render("1-9 open · ↑/↓ move · enter open · d then y delete · esc cancel")
	if p.confirm {
		footer = Caut.Render(Glyph(GlyphWarn) + " delete this session? y to confirm, any key to cancel")
	}
	return overlayBox("RESUME SESSION", body, footer, width)
}

// --- model / reasoning picker ---

type modelPicker struct {
	models  list.Model
	reasons list.Model
	focus   int // 0 = models column, 1 = reasoning column
}

// newModelPicker builds the two-column picker. When discovery yields no models it
// falls back to the current model plus a free-text note (the caller adds the
// note); the picker always has at least one selectable model.
func newModelPicker(models []string, current, reasoning string, width int) modelPicker {
	if len(models) == 0 {
		if current != "" {
			models = []string{current}
		} else {
			models = []string{"(current model)"}
		}
	}
	mItems := make([]list.Item, len(models))
	for i, m := range models {
		mItems[i] = strItem(m)
	}
	rItems := make([]list.Item, len(reasoningLevels))
	for i, r := range reasoningLevels {
		rItems[i] = strItem(r)
	}

	ml := newCompactList(mItems, 30, clampHeight(len(mItems), 8), strRow)
	rl := newCompactList(rItems, 14, len(reasoningLevels), strRow)

	for i, m := range models {
		if m == current {
			ml.Select(i)
			break
		}
	}
	if reasoning == "" {
		reasoning = "medium"
	}
	for i, r := range reasoningLevels {
		if r == reasoning {
			rl.Select(i)
			break
		}
	}
	return modelPicker{models: ml, reasons: rl}
}

func (p modelPicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch km.String() {
	case "esc":
		return p, closeOverlayCmd
	case "enter":
		model, _ := p.models.SelectedItem().(strItem)
		reason, _ := p.reasons.SelectedItem().(strItem)
		return p, func() tea.Msg {
			return modelSelectedMsg{model: string(model), reasoning: string(reason)}
		}
	case "tab", "right", "l":
		p.focus = 1
		return p, nil
	case "shift+tab", "left", "h":
		p.focus = 0
		return p, nil
	}
	// up/down (and anything else) drive the focused column.
	var cmd tea.Cmd
	if p.focus == 0 {
		p.models, cmd = p.models.Update(msg)
	} else {
		p.reasons, cmd = p.reasons.Update(msg)
	}
	return p, cmd
}

func (p modelPicker) View(width int) string {
	left := modelColumn("MODEL", p.models.View(), p.focus == 0)
	right := modelColumn("REASONING", p.reasons.View(), p.focus == 1)
	joined := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
	footer := Meta.Render("↑/↓ choose · →/tab switch column · enter apply · esc cancel")
	return overlayBox("MODEL / REASONING", joined, footer, width)
}

// modelColumn renders one picker column with a heading that brightens when the
// column has focus.
func modelColumn(title, body string, focused bool) string {
	head := Meta.Render(title)
	if focused {
		head = H2.Render(title)
	}
	return head + "\n" + body
}

// closeOverlayCmd emits the overlay-cancel message.
func closeOverlayCmd() tea.Msg { return overlayCloseMsg{} }

// clampWidth bounds a width to [lo, hi].
func clampWidth(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
