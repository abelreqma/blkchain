package main

import (
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// palette.go is the slash-command autocomplete palette (V2-BRIEF.md T5): a small
// custom panel that floats ABOVE the input while the draft is a slash command in
// progress ("/foo" with no space yet). It is intentionally NOT a bubbles/list so
// it can anchor above the input rather than replace it. The matching and filter
// logic is pure so it can be unit tested.

// maxPaletteRows caps how many command rows the panel shows before it collapses
// the rest into a "+N more" line.
const maxPaletteRows = 7

// command is one entry in the slash-command registry. name is the bare verb (no
// leading slash), args is the argument hint shown in help, desc is the one-line
// description. The registry is the single source of truth for both the palette
// and helpBlock (tui.go).
type command struct {
	name string
	args string
	desc string
}

// slashCommands is the command registry shared by the palette and helpBlock. It
// mirrors the verbs handled in submit/dispatchInput (tui.go).
func slashCommands() []command {
	return []command{
		{"ask", "<q>", "ask explicitly (rag streams a cited answer; agent runs hermes)"},
		{"mode", "", "toggle rag / agent mode (also /agent, /rag)"},
		{"agent", "", "switch to agent mode"},
		{"rag", "", "switch to rag mode"},
		{"search", "<q>", "find ranked source chunks (also: s <q>)"},
		{"open", "<N|path>", "open source N from the last answer/search, or a path"},
		{"resume", "", "reopen a saved session (1-9 quick-pick, d y deletes)"},
		{"model", "", "pick model + reasoning (also ctrl+p)"},
		{"title", "<name>", "rename the current session"},
		{"attach", "", "attach a file's contents to the next prompt (also @)"},
		{"editor", "", "compose the draft in $EDITOR (also ctrl+g)"},
		{"init", "", "load ./.blk/context.md as session context"},
		{"cost", "", "show the last turn's tokens + latency"},
		{"undo", "", "drop the last exchange from this session"},
		{"clear", "", "clear the working transcript (scrollback stays)"},
		{"copy", "", "copy the last answer to the clipboard"},
		{"hermes", "<prompt>", "run a Hermes agent turn"},
		{"health", "", "API + dependency status"},
		{"doctor", "", "diagnose the whole stack"},
		{"logs", "[name]", "tail a service log (api, embed_server)"},
		{"up", "", "start the local services"},
		{"down", "", "stop the local services"},
		{"status", "", "service status"},
		{"help", "", "this help"},
		{"quit", "", "leave (also ctrl+d)"},
	}
}

// isExactCommand reports whether name (lowercased, without the leading slash)
// exactly matches a registered command verb.
func isExactCommand(name string) bool {
	for _, c := range slashCommands() {
		if c.name == name {
			return true
		}
	}
	return false
}

// paletteItem is one filtered row: the command plus the byte positions in its
// name that matched the query (for bolding).
type paletteItem struct {
	name string
	args string
	desc string
	pos  []int
}

// palette is the transient autocomplete state. open drives whether the panel
// renders; hidden records that the operator pressed Esc for the current edit so it
// does not immediately reopen on the next keystroke (refreshPalette resets it
// once the draft leaves slash mode).
type palette struct {
	open     bool
	hidden   bool
	items    []paletteItem
	selected int
	query    string
}

// matchCommand ranks a command name against a query: prefix (rank 3) beats a
// substring (rank 2) beats a subsequence fuzzy match (rank 1). An empty query
// matches everything at rank 0. It returns the matched byte positions (for
// bolding), whether it matched, and the rank. Command names are ASCII so byte
// indexing equals rune indexing.
func matchCommand(name, query string) ([]int, bool, int) {
	if query == "" {
		return nil, true, 0
	}
	ln := strings.ToLower(name)
	lq := strings.ToLower(query)
	if strings.HasPrefix(ln, lq) {
		return seqRange(0, len(lq)), true, 3
	}
	if idx := strings.Index(ln, lq); idx >= 0 {
		return seqRange(idx, len(lq)), true, 2
	}
	// Subsequence: every query char appears in order.
	var pos []int
	qi := 0
	for i := 0; i < len(ln) && qi < len(lq); i++ {
		if ln[i] == lq[qi] {
			pos = append(pos, i)
			qi++
		}
	}
	if qi == len(lq) {
		return pos, true, 1
	}
	return nil, false, 0
}

// seqRange returns [start, start+n) as a slice of ints.
func seqRange(start, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = start + i
	}
	return out
}

// filterCommands returns the commands matching query, best rank first, ties
// broken by registry order. query is the text after the leading slash.
func filterCommands(cmds []command, query string) []paletteItem {
	query = strings.TrimSpace(query)
	type scored struct {
		item paletteItem
		rank int
		ord  int
	}
	var scoredItems []scored
	for i, c := range cmds {
		pos, ok, rank := matchCommand(c.name, query)
		if !ok {
			continue
		}
		scoredItems = append(scoredItems, scored{
			item: paletteItem{name: c.name, args: c.args, desc: c.desc, pos: pos},
			rank: rank,
			ord:  i,
		})
	}
	sort.SliceStable(scoredItems, func(i, j int) bool {
		if scoredItems[i].rank != scoredItems[j].rank {
			return scoredItems[i].rank > scoredItems[j].rank
		}
		return scoredItems[i].ord < scoredItems[j].ord
	})
	items := make([]paletteItem, len(scoredItems))
	for i, s := range scoredItems {
		items[i] = s.item
	}
	return items
}

// refreshPalette recomputes the palette from the current draft. The palette is
// active only for a single-line slash command still being typed ("/foo" with no
// space). Any space (args mode), a newline, a non-slash draft, or an Esc dismissal
// closes it.
func (m model) refreshPalette() model {
	val := strings.TrimLeft(m.ta.Value(), " ")
	active := m.overlay == nil && strings.HasPrefix(val, "/") && !strings.ContainsAny(val, " \t\n")
	if !active {
		m.pal.open = false
		m.pal.hidden = false
		return m
	}
	if m.pal.hidden {
		return m
	}
	query := strings.TrimPrefix(val, "/")
	items := filterCommands(slashCommands(), query)
	m.pal.items = items
	m.pal.query = query
	m.pal.open = len(items) > 0
	if m.pal.selected >= len(items) || m.pal.selected < 0 {
		m.pal.selected = 0
	}
	return m
}

// completeSelected writes the highlighted command into the draft (with a trailing
// space, which drops the draft into args mode and closes the palette). It never
// runs the command.
func (m model) completeSelected() model {
	if m.pal.selected < 0 || m.pal.selected >= len(m.pal.items) {
		return m
	}
	it := m.pal.items[m.pal.selected]
	m.ta.SetValue("/" + it.name + " ")
	m.ta.SetHeight(clamp(m.ta.LineCount(), 1, 6))
	m.ta.CursorEnd()
	return m.refreshPalette()
}

// paletteKey handles a key while the palette is open. It returns the updated
// model, a command, and whether it consumed the key. Navigation/complete/dismiss
// keys are consumed; everything else falls through so the textarea keeps typing.
func (m model) paletteKey(msg tea.KeyMsg) (model, tea.Cmd, bool) {
	if !m.pal.open || len(m.pal.items) == 0 {
		return m, nil, false
	}
	switch msg.String() {
	case "up":
		if m.pal.selected > 0 {
			m.pal.selected--
		}
		return m, nil, true
	case "down":
		if m.pal.selected < len(m.pal.items)-1 {
			m.pal.selected++
		}
		return m, nil, true
	case "tab":
		return m.completeSelected(), nil, true
	case "esc":
		m.pal.open = false
		m.pal.hidden = true
		return m, nil, true
	case "enter":
		name := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(m.ta.Value()), "/"))
		if isExactCommand(name) {
			m.pal.open = false
			m.pal.hidden = false
			tm, cmd := m.submit()
			return tm.(model), cmd, true
		}
		return m.completeSelected(), nil, true
	}
	return m, nil, false
}

// paletteView renders the floating panel: one rounded box (Rule border, Surface
// fill, matching the overlay style) holding up to maxPaletteRows command rows with
// the matched substring bold, then a muted "+N more" line when it overflows.
func (m model) paletteView(width int) string {
	if !m.pal.open || len(m.pal.items) == 0 {
		return ""
	}
	start := 0
	if m.pal.selected >= maxPaletteRows {
		start = m.pal.selected - maxPaletteRows + 1
	}
	end := start + maxPaletteRows
	if end > len(m.pal.items) {
		end = len(m.pal.items)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		if i > start {
			b.WriteByte('\n')
		}
		b.WriteString(paletteRow(m.pal.items[i], i == m.pal.selected))
	}
	if more := len(m.pal.items) - end; more > 0 {
		b.WriteString("\n" + Meta.Render("  +"+strconv.Itoa(more)+" more"))
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(Rule).
		Background(Surface).
		Padding(0, 1)
	if width > 24 {
		box = box.MaxWidth(width)
	}
	return box.Render(b.String())
}

// paletteRow renders one command row: a selection marker, the name with matched
// chars bold, the arg hint, and the description.
func paletteRow(it paletteItem, selected bool) string {
	marker := "  "
	base := Body
	if selected {
		marker = Prompt.Render(Glyph(GlyphPrompt)) + " "
		base = Key
	}
	name := "/" + boldMatch(it.name, it.pos, base)
	if it.args != "" {
		name += " " + Meta.Render(it.args)
	}
	return marker + name + "  " + Meta.Render(it.desc)
}

// boldMatch renders name with the byte positions in pos bolded, everything else
// in base. pos indexes into name (ASCII command names).
func boldMatch(name string, pos []int, base lipgloss.Style) string {
	if len(pos) == 0 {
		return base.Render(name)
	}
	set := make(map[int]bool, len(pos))
	for _, p := range pos {
		set[p] = true
	}
	bold := base.Bold(true)
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		ch := name[i : i+1]
		if set[i] {
			b.WriteString(bold.Render(ch))
		} else {
			b.WriteString(base.Render(ch))
		}
	}
	return b.String()
}
