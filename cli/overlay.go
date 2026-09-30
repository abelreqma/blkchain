package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"blkchain/cli/internal/histstore"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// overlay.go holds the focused overlay pickers: the /history
// session picker and the /model reasoning picker. An overlay captures keys while
// open; the base Update passes through only quit (tui.go). Each overlay renders
// over the live region, replacing the input area, inside one rounded single-line
// border in Rule with a Surface fill (per the design). Overlays never mutate the
// model directly; they emit result messages the base Update handles.

// overlayModel is the minimal contract the base loop drives: feed it a msg, get
// back the (possibly updated) overlay and a command; render it for a terminal
// of the given width and height. The size is passed on every render, so an
// overlay always fits the current terminal, including right after a resize.
type overlayModel interface {
	Update(tea.Msg) (overlayModel, tea.Cmd)
	View(width, height int) string
}

// --- overlay result messages (handled in the base Update) ---

type overlayCloseMsg struct{}               // Esc: cancel, keep current session/model
type historySelectedMsg struct{ id string } // reopen this session (/history picker)
type modelSelectedMsg struct{ model, reasoning string }

// openModelPickerMsg carries the discovered models into the model picker. Model
// discovery is a network call, so it runs in a command and opens the overlay on
// completion, keeping the event loop responsive and preserving the input draft.
// allHidden says every model but the active one is hidden in /models.
type openModelPickerMsg struct {
	models    []string
	current   string
	reasoning string
	allHidden bool
	listErr   error // the model list failed in a way worth saying (a redirect)
}

// reasoningLevels are the reasoning-effort choices, low to high.
var reasoningLevels = []string{"minimal", "low", "medium", "high"}

// --- shared list plumbing ---

// rowDelegate is a compact single-line list delegate: it defers each row's
// rendering to render(selected, item), so the pickers control the selected
// styling (Heading bold + the prompt glyph in Accent) directly.
type rowDelegate struct {
	render func(selected bool, item list.Item) string
}

func (d rowDelegate) Height() int                         { return 1 }
func (d rowDelegate) Spacing() int                        { return 0 }
func (d rowDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (d rowDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	row := d.render(index == m.Index(), item)
	// A row wider than the list is cut to fit and marked with an ASCII "...", so
	// the box border is never pushed or clipped by a long title.
	if lw := m.Width(); lw > 3 && lipgloss.Width(row) > lw {
		row = lipgloss.NewStyle().MaxWidth(lw-3).Render(row) + Meta.Render("...")
	}
	fmt.Fprint(w, row)
}

// newCompactList builds a list stripped of its title, status bar, help,
// pagination, and filtering: just a scrollable column of rows for an overlay.
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
	label := sanitizeTerminal(string(item.(strItem)))
	if selected {
		return Prompt.Render(Glyph(GlyphPrompt)) + " " + Key.Render(label)
	}
	return "  " + Body.Render(label)
}

// overlaySpec describes one overlay for overlayBox. wantW and wantRows are the
// preferred text width and body row count on a roomy terminal; minRows is the
// fewest body rows to keep before dropping chrome (0 means 3); below it the
// title goes and the body shrinks to as little as one row. body renders the
// body at the width and row count overlayBox settles on, and must fit it. Key hints are not part
// of the box: the state-aware footer under the view (footerKeys in tui.go) is
// the single source of them.
type overlaySpec struct {
	title    string
	wantW    int
	wantRows int
	minRows  int
	body     func(w, rows int) string
}

// overlayBox wraps content in the one rounded border + Surface fill the design
// prescribes, with a title heading. It fits the box to the terminal on every
// call: never wider than width-2 or taller than height-4, with every line padded
// to one width so the border stays intact. On a short terminal it first drops
// the blank spacer row, then the title, keeping at least minRows body rows.
// Shorter than that the title stays off and the body shrinks to as little as
// one row, so the smallest box is 3 rows (below height 7 it exceeds height-4).
func overlayBox(s overlaySpec, width, height int) string {
	maxOuter := max(width-2, 5)
	textW := max(min(s.wantW, maxOuter-4), 1)
	maxBox := height - 4

	floor := s.minRows
	if floor < 1 {
		floor = 3
	}
	floor = max(min(floor, s.wantRows), 1)

	type level struct{ title, gap bool }
	levels := []level{{true, true}, {true, false}, {false, false}}
	pick, rows := levels[len(levels)-1], max(min(floor, maxBox-2), 1)
	for _, lv := range levels {
		chrome := 2 // border rows
		if lv.title {
			chrome++
			if lv.gap {
				chrome++
			}
		}
		if r := min(s.wantRows, maxBox-chrome); r >= floor {
			pick, rows = lv, r
			break
		}
	}

	var parts []string
	if pick.title {
		parts = append(parts, H2.Render(s.title))
		if pick.gap {
			parts = append(parts, "")
		}
	}
	parts = append(parts, s.body(textW, rows))
	// Cut any line that still overshoots (a very narrow terminal), so the
	// padding below and the border are computed from a width every line fits.
	content := lipgloss.NewStyle().MaxWidth(textW).Render(strings.Join(parts, "\n"))
	box := lipgloss.NewStyle().
		Border(Border()).
		BorderForeground(Rule).
		Background(Surface).
		Padding(0, 1).
		Width(textW + 2)
	return box.Render(content)
}

// relTime renders a compact "n ago" for a unix timestamp.
func relTime(ts int64) string {
	if ts == 0 {
		return Glyph(GlyphDash)
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

// --- history (session) picker ---

// historyItem is one session row; num is its 1-9 quick-pick key (0 = none).
type historyItem struct {
	meta sessionMeta
	num  int
}

func (r historyItem) FilterValue() string { return r.meta.Title }

type historyPicker struct {
	list    list.Model
	metas   []sessionMeta
	confirm bool   // 'd' pressed, awaiting 'y'
	title   string // box title
	// store and titles back the /history picker: delete erases from the store and
	// reload re-queries it, so the picker stays consistent with how /history lists
	// and with /history clear. When store is nil the picker falls back to the JSONL
	// session store (used by rendering/layout tests that need no live store).
	store  *histstore.Store
	titles map[string]string
}

// newHistoryPicker builds the picker from the given session list, selecting the
// current session if present. It is the /history picker; selecting a row emits
// historySelectedMsg.
func newHistoryPicker(metas []sessionMeta, currentID string, width int) historyPicker {
	items := historyItems(metas)
	w := clamp(width-6, 30, 72)
	h := clamp(len(items), 1, 9)
	l := newCompactList(items, w, h, historyRow)
	for i, m := range metas {
		if m.ID == currentID {
			l.Select(i)
			break
		}
	}
	return historyPicker{list: l, metas: metas, title: "HISTORY"}
}

func historyItems(metas []sessionMeta) []list.Item {
	items := make([]list.Item, len(metas))
	for i, m := range metas {
		num := 0
		if i < 9 {
			num = i + 1
		}
		items[i] = historyItem{meta: m, num: num}
	}
	return items
}

func historyRow(selected bool, item list.Item) string {
	r := item.(historyItem)
	title := strings.TrimSpace(sanitizeTerminal(r.meta.Title))
	if title == "" {
		title = r.meta.ID
	}
	num := "  "
	if r.num > 0 {
		num = fmt.Sprintf("%d ", r.num)
	}
	meta := joinSep(fmt.Sprintf("%d msgs", r.meta.MsgCount), relTime(r.meta.UpdatedAt))
	if selected {
		return Prompt.Render(Glyph(GlyphPrompt)) + " " + Key.Render(num) + Key.Render(title) + "  " + Meta.Render(meta)
	}
	return "  " + Meta.Render(num) + Body.Render(title) + "  " + Meta.Render(meta)
}

func (p historyPicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		p.list, cmd = p.list.Update(msg)
		return p, cmd
	}
	s := km.String()

	if p.confirm {
		if s == "y" || s == "Y" {
			if it, ok := p.list.SelectedItem().(historyItem); ok {
				if p.store != nil {
					purgeHistorySession(p.store, it.meta.ID)
				} else {
					_ = deleteSession(it.meta.ID)
				}
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
		if it, ok := p.list.SelectedItem().(historyItem); ok {
			id := it.meta.ID
			return p, func() tea.Msg { return historySelectedMsg{id: id} }
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
			return p, func() tea.Msg { return historySelectedMsg{id: id} }
		}
		return p, nil
	}

	var cmd tea.Cmd
	p.list, cmd = p.list.Update(msg)
	return p, cmd
}

// reload rebuilds the picker after a delete, re-querying the same source the
// picker was opened from: the langchaingo store for /history, or the JSONL
// session list as a fallback when no store is attached.
func (p historyPicker) reload() historyPicker {
	var metas []sessionMeta
	if p.store != nil {
		hs, _ := p.store.Sessions(context.Background())
		metas = mergeHistoryMetas(hs, p.titles)
	} else {
		metas, _ = listSessions()
	}
	p.metas = metas
	p.list.SetItems(historyItems(metas))
	p.list.SetHeight(clamp(len(metas), 1, 9))
	return p
}

func (p historyPicker) View(width, height int) string {
	// The list is sized to the box on every render (p is a copy, so the stored
	// list keeps no stale geometry). SetSize keeps the selected row on screen.
	body := func(w, rows int) string {
		if len(p.metas) == 0 {
			return Meta.Render("no saved sessions yet")
		}
		p.list.SetSize(w, rows)
		return p.list.View()
	}
	return overlayBox(overlaySpec{
		title: p.title,
		wantW: 72, wantRows: clamp(len(p.metas), 1, 9), body: body,
	}, width, height)
}

// --- model / reasoning picker ---

type modelPicker struct {
	models  list.Model
	reasons list.Model
	focus   int    // 0 = models column, 1 = reasoning column
	hint    string // a muted line under the columns, when set
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

	ml := newCompactList(mItems, 30, clamp(len(mItems), 1, 8), strRow)
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

func (p modelPicker) View(width, height int) string {
	// Both columns are sized to the box on every render. The reasoning column
	// is at most 14 wide (a third of the box when narrow), the model column
	// takes the rest, and each column is padded to a fixed width so the
	// reasoning column does not shift as the selection changes.
	body := func(w, rows int) string {
		hint := ""
		if p.hint != "" && rows > 2 {
			rows--
			hint = "\n" + Meta.Render(ellipsize(p.hint, w))
		}
		rw := clamp(w/3, 9, 14)
		mw := max(min(w-2-rw, 30), 8)
		// One row goes to the column heading, unless that would leave no list row.
		listRows := max(rows-1, 1)
		p.models.SetSize(mw, listRows)
		p.reasons.SetSize(rw, min(len(reasoningLevels), listRows))
		pad := func(cw int, s string) string { return lipgloss.NewStyle().Width(cw).Render(s) }
		left, right := p.models.View(), p.reasons.View()
		if rows > 1 {
			left = modelColumn("MODEL", left, p.focus == 0)
			right = modelColumn("REASONING", right, p.focus == 1)
		}
		left, right = pad(mw, left), pad(rw, right)
		return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right) + hint
	}
	hintRows := 0
	if p.hint != "" {
		hintRows = 1
	}
	return overlayBox(overlaySpec{
		title: "MODEL / REASONING",
		wantW: 46, wantRows: 1 + max(min(len(p.models.Items()), 8), len(reasoningLevels)) + hintRows,
		minRows: 4, body: body,
	}, width, height)
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
