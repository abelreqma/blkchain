package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// modelspanel.go is /models: a panel listing every model with its state, where
// a key turns one on or off, loads or unloads it, or makes it the active chat
// model; and the same actions as slash arguments for both REPLs. Model ids and
// sizes come from the LLM server, so every displayed string is sanitized.

// modelsData is what /models fetches: the chat models, embed_server's health,
// and whether web search is configured.
type modelsData struct {
	chat    []chatModel
	admin   bool  // the admin API answered, so the loaded state is known
	chatErr error // listing the chat models failed
	embedUp bool  // embed_server answered GET /health
	embed   embedHealth
	// webProvider is the active web-search provider (activeWebProvider):
	// "tavily", "duckduckgo", or "off". Web search is available whenever it is
	// not "off", whether configured by a Tavily key or the keyless fallback.
	webProvider string
}

// fetchModelsData does the network work behind /models. It is called from a
// command in the TUI and directly in the plain REPL.
func fetchModelsData() modelsData {
	ctx, cancel := context.WithTimeout(context.Background(), modelsListTimeout)
	defer cancel()
	var d modelsData
	d.chat, d.admin, d.chatErr = fetchChatModels(ctx)
	d.embed, d.embedUp = probeEmbedHealth(loadConfig())
	d.webProvider = activeWebProvider()
	return d
}

// rowKind says what a /models row is, which decides what its keys do.
type rowKind int

const (
	rowChat rowKind = iota
	rowEmbedder
	rowReranker
	rowWeb
	rowRag
)

// modelRow is one /models row: its group heading, name, state words, and
// detail parts (size, context length, and so on). id is the chat model id (chat
// rows only).
type modelRow struct {
	kind            rowKind
	group, name, id string
	state           string
	detail          []string
}

// modelRows builds the rows: the chat models, then the embedder and reranker,
// then web search. loading holds the loads started from the panel. The active
// model always has a row, even when the server does not list it.
func modelRows(d modelsData, p modelPrefs, active string, loading map[string]bool) []modelRow {
	chat := d.chat
	if active != "" && !slices.ContainsFunc(chat, func(c chatModel) bool { return c.ID == active }) {
		chat = append([]chatModel{{ID: active}}, chat...)
	}
	var rows []modelRow
	for _, c := range chat {
		var states []string
		if c.ID == active {
			states = append(states, "active")
		}
		switch {
		case c.Loading || loading[c.ID]:
			states = append(states, "loading")
		case c.ID == active:
		case !c.Known:
			states = append(states, "unknown")
		case c.Loaded:
			states = append(states, "loaded")
		default:
			states = append(states, "not loaded")
		}
		if p.isHidden(c.ID) {
			states = append(states, "hidden")
		}
		var detail []string
		if c.Size != "" {
			detail = append(detail, c.Size)
		}
		if c.Context >= 1024 {
			detail = append(detail, fmt.Sprintf("%dk ctx", c.Context/1024))
		} else if c.Context > 0 {
			detail = append(detail, fmt.Sprintf("%d ctx", c.Context))
		}
		if c.Default {
			detail = append(detail, "default")
		}
		rows = append(rows, modelRow{kind: rowChat, group: "CHAT", name: c.ID, id: c.ID,
			state: strings.Join(states, ", "), detail: detail})
	}

	embed, rerank := "down", "down"
	if d.embedUp && d.embed.Embedder {
		embed = "ready"
	}
	if d.embedUp && d.embed.Reranker {
		rerank = "on"
	}
	if !p.Rerank {
		rerank = "off"
	}
	rag := "on"
	if !p.Rag {
		rag = "off"
	}
	web, webDetail := "off", []string(nil)
	switch d.webProvider {
	case webProviderTavily:
		webDetail = []string{"tavily"}
		if p.Web {
			web = "on"
		}
	case webProviderDuckDuckGo:
		webDetail = []string{"duckduckgo fallback"}
		if p.Web {
			web = "on"
		}
	default:
		web, webDetail = "not configured", []string{"set TAVILY_SETUP_TOKEN or DuckDuckGo"}
	}
	return append(rows,
		modelRow{kind: rowEmbedder, group: "RETRIEVAL", name: "embedder", state: embed},
		modelRow{kind: rowReranker, group: "RETRIEVAL", name: "reranker", state: rerank},
		modelRow{kind: rowRag, group: "RETRIEVAL", name: "rag", state: rag},
		modelRow{kind: rowWeb, group: "WEB", name: "web search", state: web, detail: webDetail},
	)
}

// stateStyle colors a state by its first word. The word carries the meaning;
// the color only adds to it.
func stateStyle(state string) lipgloss.Style {
	first, _, _ := strings.Cut(state, ",")
	switch first {
	case "active", "loaded", "on", "ready":
		return OK
	case "loading":
		return Caut
	case "down":
		return Fail
	}
	return Meta
}

// modelLines renders rows under their group headings in columns (marker, name,
// state, detail) at most w wide. sel is the selected row (-1 for none); it
// returns the lines and the index of the selected row's line. The name gives
// way before the state; detail parts that do not fit are dropped from the end.
func modelLines(rows []modelRow, sel, w int) ([]string, int) {
	names := make([]string, len(rows))
	nameMax, stateW := 0, 0
	for i, r := range rows {
		names[i] = oneLine(sanitizeTerminal(r.name))
		nameMax = max(nameMax, lipgloss.Width(names[i]))
		stateW = max(stateW, len(r.state))
	}
	avail := max(w-2-2-stateW, 1)
	nameW := min(nameMax, avail)
	detailW := avail - nameW - 2

	var lines []string
	selLine, group := 0, ""
	for i, r := range rows {
		if r.group != group {
			group = r.group
			lines = append(lines, Meta.Render(group))
		}
		marker, nameStyle := "  ", Body
		if i == sel {
			marker, nameStyle, selLine = Prompt.Render(Glyph(GlyphPrompt))+" ", Key, len(lines)
		}
		detail := fitDetail(r.detail, detailW)
		line := marker + nameStyle.Render(padCols(ellipsize(names[i], nameW), nameW)) + "  "
		if detail == "" {
			line += stateStyle(r.state).Render(r.state)
		} else {
			line += stateStyle(r.state).Render(padCols(r.state, stateW)) + "  " + Meta.Render(detail)
		}
		lines = append(lines, line)
	}
	return lines, selLine
}

// fitDetail joins as many sanitized detail parts as fit in w columns. A first
// part too long on its own is cut; under 6 columns there is no detail.
func fitDetail(parts []string, w int) string {
	if len(parts) == 0 || w < 6 {
		return ""
	}
	clean := make([]string, len(parts))
	for i, p := range parts {
		clean[i] = oneLine(sanitizeTerminal(p))
	}
	for n := len(clean); n > 0; n-- {
		if s := joinSep(clean[:n]...); lipgloss.Width(s) <= w {
			return s
		}
	}
	return ellipsize(clean[0], w)
}

// setModelSwitch turns one model on or off in p: a chat model shown or hidden
// in the model picker, or the reranker or web search on or off. It refuses to
// hide the active model, to turn off the embedder, and to change web search
// while no provider is available. webSet is that availability (a Tavily key or
// the keyless fallback). It returns the new settings and what changed.
func setModelSwitch(p modelPrefs, kind rowKind, id string, on bool, active string, webSet bool) (modelPrefs, string, error) {
	switch kind {
	case rowEmbedder:
		if on {
			return p, "the embedder is always on", nil
		}
		return p, "", errors.New("the embedder cannot be turned off: retrieval needs it")
	case rowReranker:
		p.Rerank = on
		if on {
			return p, "reranker on", nil
		}
		return p, "reranker off: answers keep the hybrid search order", nil
	case rowWeb:
		if !webSet && on {
			return p, "", errors.New("web search is not configured: set TAVILY_SETUP_TOKEN or DuckDuckGo")
		}
		p.Web = on
		if on {
			return p, "web search on", nil
		}
		return p, "web search off: answers never search the web", nil
	case rowRag:
		p.Rag = on
		if on {
			return p, "rag on", nil
		}
		return p, "rag off: answers never query the local knowledge base", nil
	}
	if on {
		return p.withHidden(id, false), id + " is shown in the model picker", nil
	}
	if id == active {
		return p, "", fmt.Errorf("cannot hide %s: it is the active model; pick another model first", id)
	}
	return p.withHidden(id, true), id + " is hidden from the model picker", nil
}

// runModelAction loads or unloads a chat model, bounded by the load or unload
// timeout.
func runModelAction(id, action string) error {
	timeout := modelUnloadTimeout
	if action == "load" {
		timeout = modelLoadTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return llmModelAction(ctx, id, action)
}

// modelActionNote is the one-line result of a finished load or unload.
func modelActionNote(id, action string, active bool) string {
	note := action + "ed " + id
	if action == "unload" && active {
		note += "; the next answer will reload it"
	}
	return note
}

// --- slash arguments, shared by both REPLs ---

var errModelsUsage = errors.New("models: use /models to see every model, or /models on|off|load|unload <name>")

// parseModelsArgs splits "/models <verb> <name>" arguments.
func parseModelsArgs(arg string) (verb, name string, err error) {
	verb, name = splitFirst(arg)
	verb = strings.ToLower(verb)
	switch verb {
	case "on", "off", "load", "unload":
	default:
		return "", "", errModelsUsage
	}
	if name == "" {
		return "", "", fmt.Errorf("models %s: name a model: a chat model id, reranker, rag, or web", verb)
	}
	return verb, name, nil
}

// resolveChatModel finds the chat model name refers to: an exact id, else the
// one id it is a prefix of (ignoring case). An ambiguous prefix lists the
// candidates.
func resolveChatModel(name string, models []chatModel) (string, error) {
	var hits []string
	for _, m := range models {
		if m.ID == name {
			return m.ID, nil
		}
		if strings.HasPrefix(strings.ToLower(m.ID), strings.ToLower(name)) {
			hits = append(hits, m.ID)
		}
	}
	switch {
	case len(hits) == 1:
		return hits[0], nil
	case len(hits) == 0:
		return "", fmt.Errorf("no model named %q; run /models to list them", name)
	case len(hits) > 8:
		hits = append(hits[:8], fmt.Sprintf("and %d more", len(hits)-8))
	}
	return "", fmt.Errorf("%q matches %s; type more of the name", name, strings.Join(hits, ", "))
}

// modelSwitch is the one switch a "/models on|off <name>" turns: a chat model
// shown or hidden in the model picker, or the reranker or web search on or off.
// webSet is whether web search was available (a provider configured) when the
// command ran.
type modelSwitch struct {
	kind   rowKind
	id     string
	on     bool
	webSet bool
}

// runModelsArgs carries out one "/models on|off|load|unload <name>". name is a
// chat model id or a unique prefix of one, or reranker or web. It may call the
// LLM server, so the TUI runs it in a command. A load or unload returns what
// happened. On and off return only the switch to turn: the caller applies it
// to the settings it holds now (see setModelSwitch) and saves them, so a
// change made while this ran is kept.
func runModelsArgs(verb, name, active string) (string, *modelSwitch, error) {
	kind := rowChat
	switch strings.ToLower(name) {
	case "embedder":
		kind = rowEmbedder
	case "reranker":
		kind = rowReranker
	case "web":
		kind = rowWeb
	case "rag":
		kind = rowRag
	}
	id := ""
	var admin bool
	if kind == rowChat {
		ctx, cancel := context.WithTimeout(context.Background(), modelsListTimeout)
		defer cancel()
		models, adm, err := fetchChatModels(ctx)
		if err != nil {
			return "", nil, err
		}
		if id, err = resolveChatModel(name, models); err != nil {
			return "", nil, err
		}
		admin = adm
	}
	if verb == "load" || verb == "unload" {
		if kind != rowChat {
			return "", nil, errors.New("only chat models can be loaded or unloaded")
		}
		if !admin {
			return "", nil, fmt.Errorf("%s: %w", verb, errLLMUnsupported)
		}
		if err := runModelAction(id, verb); err != nil {
			return "", nil, fmt.Errorf("%s %s: %w", verb, id, err)
		}
		return modelActionNote(id, verb, id == active), nil, nil
	}
	return "", &modelSwitch{kind: kind, id: id, on: verb == "on", webSet: activeWebProvider() != webProviderNone}, nil
}

// replModels is /models in the plain REPL: with no arguments it prints every
// model and its state; otherwise it runs runModelsArgs and saves a switch.
func replModels(arg string) error {
	active := ragModelLabel()
	if strings.TrimSpace(arg) == "" {
		d := fetchModelsData()
		lines, _ := modelLines(modelRows(d, loadPrefs(), active, nil), -1, terminalWidth()-1)
		for _, ln := range lines {
			fmt.Println(" " + ln)
		}
		if d.chatErr != nil {
			fmt.Println(styleErr(fmt.Errorf("chat models: %w", d.chatErr)))
		}
		return nil
	}
	verb, name, err := parseModelsArgs(arg)
	if err != nil {
		return err
	}
	note, sw, err := runModelsArgs(verb, name, active)
	if err != nil {
		return err
	}
	if sw != nil {
		var np modelPrefs
		if np, note, err = setModelSwitch(loadPrefs(), sw.kind, sw.id, sw.on, active, sw.webSet); err != nil {
			return err
		}
		if err := savePrefs(np); err != nil {
			return fmt.Errorf("saving the model settings: %w", err)
		}
	}
	fmt.Println(Meta.Render(oneLine(sanitizeTerminal(note))))
	return nil
}

// --- TUI messages and commands ---

// modelsDataMsg carries a fetch into the open panel.
// listed is the model a turn uses when none is picked (see listedModel), ""
// when the server did not say.
type modelsDataMsg struct {
	data   modelsData
	listed string
}

// modelActionDoneMsg ends a load or unload started from the panel.
type modelActionDoneMsg struct {
	id, action string
	err        error
}

// prefsChangedMsg carries a switch the panel changed; the base Update keeps it
// and saves it.
type prefsChangedMsg struct{ prefs modelPrefs }

// prefsSavedMsg reports the save of the model settings.
type prefsSavedMsg struct{ err error }

// modelsArgsDoneMsg ends a "/models <verb> <name>" run in the TUI: a note, or
// the switch the base Update applies to its settings and saves.
type modelsArgsDoneMsg struct {
	note string
	sw   *modelSwitch
	err  error
}

// fetchModelsCmd fetches the panel's data and, with it, the model a turn uses,
// so the first list that loads also resolves the active model.
func fetchModelsCmd() tea.Msg {
	return modelsDataMsg{data: fetchModelsData(), listed: listedModel()}
}

func modelActionCmd(id, action string) tea.Cmd {
	return func() tea.Msg {
		return modelActionDoneMsg{id: id, action: action, err: runModelAction(id, action)}
	}
}

// prefsSaves orders the panel's saves. savePrefsCmd numbers each save when the
// base Update asks for it, so in the order of the toggles; a save whose number
// is older than one already written is dropped, so the file always ends with
// the newest settings however the commands are scheduled.
var prefsSaves struct {
	mu      sync.Mutex
	next    uint64
	written uint64
}

func savePrefsCmd(p modelPrefs) tea.Cmd {
	prefsSaves.mu.Lock()
	prefsSaves.next++
	seq := prefsSaves.next
	prefsSaves.mu.Unlock()
	return func() tea.Msg {
		prefsSaves.mu.Lock()
		defer prefsSaves.mu.Unlock()
		if seq < prefsSaves.written {
			return prefsSavedMsg{}
		}
		prefsSaves.written = seq
		return prefsSavedMsg{err: savePrefs(p)}
	}
}

func modelsArgsCmd(verb, name, active string) tea.Cmd {
	return func() tea.Msg {
		note, sw, err := runModelsArgs(verb, name, active)
		return modelsArgsDoneMsg{note: note, sw: sw, err: err}
	}
}

// --- the panel ---

// modelsPanel is the /models overlay. loading marks loads started here, shown
// as loading until the list refreshes; armed is the active model awaiting the
// second u that unloads it; note is the one-line result or error, and fetching
// marks it as the fetch-in-progress note the next list replaces.
type modelsPanel struct {
	data     modelsData
	fetched  bool
	prefs    modelPrefs
	active   string
	loading  map[string]bool
	sel      int
	armed    string
	note     string
	noteErr  bool
	fetching bool
}

func newModelsPanel(p modelPrefs, active string) modelsPanel {
	return modelsPanel{prefs: p, active: active, note: "checking the models" + ellipsis(), fetching: true}
}

func (p modelsPanel) rows() []modelRow { return modelRows(p.data, p.prefs, p.active, p.loading) }

// chat returns the listed chat model with id (the zero value when unlisted).
func (p modelsPanel) chat(id string) chatModel {
	for _, c := range p.data.chat {
		if c.ID == id {
			return c
		}
	}
	return chatModel{}
}

func (p modelsPanel) setNote(note string, isErr bool) modelsPanel {
	p.note, p.noteErr, p.fetching = note, isErr, false
	return p
}

func (p modelsPanel) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	switch msg := msg.(type) {
	case modelsDataMsg:
		// Keep the selected row across a refresh; the first list opens on the
		// active model.
		prev := p.rows()[p.sel]
		if !p.fetched {
			prev = modelRow{kind: rowChat, id: p.active}
		}
		p.data, p.fetched = msg.data, true
		if p.fetching {
			p = p.setNote("", false)
		}
		if msg.data.chatErr != nil {
			p = p.setNote("chat models: "+msg.data.chatErr.Error(), true)
		}
		p.sel = max(slices.IndexFunc(p.rows(), func(r modelRow) bool { return r.kind == prev.kind && r.id == prev.id }), 0)
		return p, nil
	case modelActionDoneMsg:
		p.loading = maps.Clone(p.loading)
		delete(p.loading, msg.id)
		if msg.err != nil {
			return p.setNote(fmt.Sprintf("%s %s: %v", msg.action, msg.id, msg.err), true), fetchModelsCmd
		}
		return p.setNote(modelActionNote(msg.id, msg.action, msg.id == p.active), false), fetchModelsCmd
	case tea.KeyMsg:
		return p.key(msg.String())
	}
	return p, nil
}

func (p modelsPanel) key(k string) (overlayModel, tea.Cmd) {
	if id := p.armed; id != "" {
		p.armed = ""
		if k != "u" {
			return p.setNote("", false), nil // any other key cancels the unload
		}
		return p.setNote("unloading "+id+ellipsis(), false), modelActionCmd(id, "unload")
	}
	rows := p.rows()
	r := rows[p.sel]
	switch k {
	case "esc":
		return p, closeOverlayCmd
	case "up", "down":
		if k == "up" && p.sel > 0 {
			p.sel--
		}
		if k == "down" && p.sel < len(rows)-1 {
			p.sel++
		}
		return p.setNote("", false), nil
	case "r":
		p = p.setNote("refreshing"+ellipsis(), false)
		p.fetching = true
		return p, fetchModelsCmd
	case "enter":
		if r.kind == rowChat {
			id := r.id
			return p, func() tea.Msg { return modelSelectedMsg{model: id} }
		}
	case " ":
		on := false
		switch r.kind {
		case rowChat:
			on = p.prefs.isHidden(r.id)
		case rowReranker:
			on = !p.prefs.Rerank
		case rowWeb:
			on = !p.prefs.Web
		case rowRag:
			on = !p.prefs.Rag
		}
		np, note, err := setModelSwitch(p.prefs, r.kind, r.id, on, p.active, p.data.webProvider != webProviderNone)
		if err != nil {
			return p.setNote(err.Error(), true), nil
		}
		p.prefs = np
		return p.setNote(note, false), func() tea.Msg { return prefsChangedMsg{prefs: np} }
	case "l", "u":
		return p.loadOrUnload(r, map[string]string{"l": "load", "u": "unload"}[k])
	}
	return p, nil
}

// loadOrUnload starts a load or unload of the selected chat model. A load shows
// loading at once; unloading the active model first asks for a second u.
func (p modelsPanel) loadOrUnload(r modelRow, action string) (overlayModel, tea.Cmd) {
	switch {
	case r.kind != rowChat:
		return p.setNote("only chat models can be loaded or unloaded", true), nil
	case !p.data.admin:
		return p.setNote(action+": "+errLLMUnsupported.Error(), true), nil
	}
	c := p.chat(r.id)
	busy := c.Loading || p.loading[r.id]
	if action == "load" {
		if busy || c.Loaded {
			return p.setNote(r.id+" is already loaded or loading", false), nil
		}
		p.loading = maps.Clone(p.loading)
		if p.loading == nil {
			p.loading = map[string]bool{}
		}
		p.loading[r.id] = true
		return p.setNote("loading "+r.id+", this can take a few minutes", false), modelActionCmd(r.id, "load")
	}
	if !busy && !c.Loaded {
		return p.setNote(r.id+" is not loaded", false), nil
	}
	if r.id == p.active {
		p.armed = r.id
		return p.setNote("press u again to unload "+r.id+"; the next answer will reload it", false), nil
	}
	return p.setNote("unloading "+r.id+ellipsis(), false), modelActionCmd(r.id, "unload")
}

// hints is the panel's state-aware footer: the keys that act on the selected
// row, or the confirm keys while an unload waits for its second u.
func (p modelsPanel) hints(closeKey key.Binding) []key.Binding {
	if p.armed != "" {
		return []key.Binding{hint("u", "confirm unload"), hint("ctrl+d", "quit"), hint("any other key", "cancel")}
	}
	out := []key.Binding{hint("up/down", "move")}
	r := p.rows()[p.sel]
	onOff := func(on bool) key.Binding {
		if on {
			return hint("space", "turn off")
		}
		return hint("space", "turn on")
	}
	switch r.kind {
	case rowChat:
		if r.id != p.active {
			if p.prefs.isHidden(r.id) {
				out = append(out, hint("space", "show"))
			} else {
				out = append(out, hint("space", "hide"))
			}
		}
		if p.data.admin {
			if c := p.chat(r.id); c.Loaded || c.Loading || p.loading[r.id] {
				out = append(out, hint("u", "unload"))
			} else {
				out = append(out, hint("l", "load"))
			}
		}
		out = append(out, hint("enter", "use"))
	case rowEmbedder:
		out = append(out, hint("embedder", "always on for retrieval"))
	case rowReranker:
		out = append(out, onOff(p.prefs.Rerank))
	case rowRag:
		out = append(out, onOff(p.prefs.Rag))
	case rowWeb:
		if p.data.webProvider != webProviderNone {
			out = append(out, onOff(p.prefs.Web))
		}
	}
	return append(out, hint("r", "refresh"), closeKey)
}

func (p modelsPanel) View(width, height int) string {
	rows := p.rows()
	all, _ := modelLines(rows, p.sel, 76)
	body := func(w, n int) string {
		lines, selLine := modelLines(rows, p.sel, w)
		// The last row is the note, unless that would leave no row for the list.
		listRows := max(n-1, 1)
		start := clamp(selLine-listRows+1, 0, max(len(lines)-listRows, 0))
		out := lines[start:min(start+listRows, len(lines))]
		if n > 1 {
			note := oneLine(sanitizeTerminal(p.note))
			if hidden := len(lines) - len(out); note == "" && hidden > 0 {
				note = fmt.Sprintf("+%d more lines, up/down to scroll", hidden)
			}
			if p.noteErr {
				mark := Glyph(GlyphErr) + " "
				note = Fail.Render(mark) + Body.Render(ellipsize(note, w-lipgloss.Width(mark)))
			} else {
				note = Meta.Render(ellipsize(note, w))
			}
			out = append(out, note)
		}
		return strings.Join(out, "\n")
	}
	// minRows is every line: a short terminal drops the title before a row.
	return overlayBox(overlaySpec{
		title: "MODELS",
		wantW: 76, wantRows: len(all) + 1, minRows: len(all) + 1, body: body,
	}, width, height)
}
