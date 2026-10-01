package main

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var keySpace = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}

// drain runs cmd and every command a batch or sequence holds, returning the
// messages in order.
func drain(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Slice && v.Type().Elem() == reflect.TypeOf(tea.Cmd(nil)) {
		var out []tea.Msg
		for i := 0; i < v.Len(); i++ {
			out = append(out, drain(v.Index(i).Interface().(tea.Cmd))...)
		}
		return out
	}
	return []tea.Msg{msg}
}

// panelData is three chat models (active and loaded, hidden, idle), a ready
// embedder, a ready reranker, and configured web search.
func panelData() modelsData {
	return modelsData{
		chat: []chatModel{
			{ID: "act-model", Loaded: true, Known: true, Size: "13.89 GB", Context: 262144, Default: true},
			{ID: "hid-model", Known: true},
			{ID: "idle-model", Known: true},
		},
		admin: true, embedUp: true, embed: embedHealth{Embedder: true, Reranker: true}, webProvider: webProviderTavily,
	}
}

// panelModel is a TUI model at w x h with the /models panel open on panelData,
// "hid-model" hidden and "act-model" active.
func panelModel(t *testing.T, w, h int) model {
	t.Helper()
	m := newKeyModel(t)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	m = nm.(model)
	m.ragModel = "act-model"
	m.prefs = defaultPrefs().withHidden("hid-model", true)
	m.overlay = newModelsPanel(m.prefs, m.currentModel())
	nm, _ = m.Update(modelsDataMsg{data: panelData()})
	return nm.(model)
}

func panelOf(t *testing.T, m model) modelsPanel {
	t.Helper()
	p, ok := m.overlay.(modelsPanel)
	if !ok {
		t.Fatalf("overlay = %T, want the models panel", m.overlay)
	}
	return p
}

// step presses k and feeds the panel, prefs, and close messages its commands
// produce back through Update, following their commands in turn. It returns
// the model and every message seen.
func step(t *testing.T, m model, k tea.Msg) (model, []tea.Msg) {
	t.Helper()
	nm, cmd := m.Update(k)
	m = nm.(model)
	var seen []tea.Msg
	queue := drain(cmd)
	for len(queue) > 0 {
		msg := queue[0]
		queue = queue[1:]
		seen = append(seen, msg)
		switch msg.(type) {
		case prefsChangedMsg, prefsSavedMsg, modelActionDoneMsg, modelsDataMsg, overlayCloseMsg:
			nm, cmd := m.Update(msg)
			m = nm.(model)
			queue = append(queue, drain(cmd)...)
		}
	}
	return m, seen
}

// selectRow moves the selection to the row named name with up and down.
func selectRow(t *testing.T, m model, name string) model {
	t.Helper()
	target := slices.IndexFunc(panelOf(t, m).rows(), func(r modelRow) bool { return r.name == name })
	if target < 0 {
		t.Fatalf("no row %q", name)
	}
	for p := panelOf(t, m); p.sel != target; p = panelOf(t, m) {
		k := tea.KeyMsg{Type: tea.KeyDown}
		if p.sel > target {
			k = tea.KeyMsg{Type: tea.KeyUp}
		}
		m, _ = step(t, m, k)
	}
	return m
}

func rowState(t *testing.T, m model, name string) string {
	t.Helper()
	for _, r := range panelOf(t, m).rows() {
		if r.name == name {
			return r.state
		}
	}
	t.Fatalf("no row %q", name)
	return ""
}

func TestModelsPanelRowsAndStates(t *testing.T) {
	isolateUserDirs(t)
	m := panelModel(t, 100, 30)
	for name, want := range map[string]string{
		"act-model": "active", "hid-model": "not loaded, hidden", "idle-model": "not loaded",
		"embedder": "ready", "reranker": "on", "web search": "on",
	} {
		if got := rowState(t, m, name); got != want {
			t.Errorf("%s state = %q, want %q", name, got, want)
		}
	}
	d := panelData()
	d.embedUp, d.admin = false, false
	d.webProvider = webProviderNone
	d.chat = []chatModel{{ID: "act-model"}, {ID: "other"}}
	nm, _ := m.Update(modelsDataMsg{data: d})
	m = nm.(model)
	for name, want := range map[string]string{
		"other": "unknown", "embedder": "down", "reranker": "down", "web search": "not configured",
	} {
		if got := rowState(t, m, name); got != want {
			t.Errorf("down: %s state = %q, want %q", name, got, want)
		}
	}
	view := m.View()
	full := panelModel(t, 100, 30).View()
	for _, g := range []string{"CHAT", "RETRIEVAL", "WEB", "13.89 GB", "256k ctx"} {
		if !strings.Contains(full, g) {
			t.Errorf("panel view lacks %q:\n%s", g, full)
		}
	}
	if !strings.Contains(view, "not configured") {
		t.Errorf("view lacks the web state:\n%s", view)
	}
}

func TestModelsPanelMoveAndClose(t *testing.T) {
	m := panelModel(t, 100, 30)
	if r := panelOf(t, m).rows()[panelOf(t, m).sel]; r.name != "act-model" {
		t.Errorf("panel opens on %q, want the active model", r.name)
	}
	m, _ = step(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if p := panelOf(t, m); p.rows()[p.sel].name != "hid-model" {
		t.Errorf("down selects %q", p.rows()[p.sel].name)
	}
	m, _ = step(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if p := panelOf(t, m); p.rows()[p.sel].name != "act-model" {
		t.Errorf("up selects %q", p.rows()[p.sel].name)
	}
	m, _ = step(t, m, keyEsc)
	if m.overlay != nil {
		t.Error("esc should close the panel")
	}
	m = panelModel(t, 100, 30)
	m, _ = step(t, m, keyCtrlC)
	if m.overlay != nil {
		t.Error("ctrl+c should close the panel")
	}
}

func TestModelsPanelSpaceTogglesAndSaves(t *testing.T) {
	m := panelModel(t, 100, 30)

	// The active model cannot be hidden, and the panel says why.
	m, _ = step(t, m, keySpace)
	if m.prefs.isHidden("act-model") {
		t.Fatal("the active model was hidden")
	}
	if v := m.View(); !strings.Contains(v, "active model") {
		t.Errorf("no reason shown for refusing to hide the active model:\n%s", v)
	}

	m = selectRow(t, m, "hid-model")
	m, _ = step(t, m, keySpace)
	if m.prefs.isHidden("hid-model") || loadPrefs().isHidden("hid-model") {
		t.Error("space should show the hidden model, in memory and on disk")
	}
	if got := rowState(t, m, "hid-model"); got != "not loaded" {
		t.Errorf("state after showing = %q", got)
	}
	m, _ = step(t, m, keySpace)
	if !m.prefs.isHidden("hid-model") || !loadPrefs().isHidden("hid-model") {
		t.Error("space again should hide it")
	}

	m = selectRow(t, m, "reranker")
	m, _ = step(t, m, keySpace)
	if m.prefs.Rerank || loadPrefs().Rerank || rowState(t, m, "reranker") != "off" {
		t.Error("space on the reranker should turn it off and save it")
	}

	m = selectRow(t, m, "web search")
	m, _ = step(t, m, keySpace)
	if m.prefs.Web || rowState(t, m, "web search") != "off" {
		t.Error("space on web search should turn it off")
	}

	m = selectRow(t, m, "embedder")
	before := m.prefs
	m, _ = step(t, m, keySpace)
	if !reflect.DeepEqual(m.prefs, before) {
		t.Error("the embedder must not toggle")
	}
	if v := m.View(); !strings.Contains(v, "retrieval needs it") {
		t.Errorf("no reason shown for the embedder:\n%s", v)
	}
	if f := m.footer(); !strings.Contains(f, "always on") {
		t.Errorf("footer on the embedder row = %q, want it to say it stays on", f)
	}
}

func TestModelsPanelWebNotConfiguredDoesNotToggle(t *testing.T) {
	m := panelModel(t, 100, 30)
	d := panelData()
	d.webProvider = webProviderNone
	nm, _ := m.Update(modelsDataMsg{data: d})
	m = selectRow(t, nm.(model), "web search")
	m, _ = step(t, m, keySpace)
	if !m.prefs.Web {
		t.Error("an unconfigured web search must not toggle")
	}
	if v := m.View(); !strings.Contains(v, "TAVILY_SETUP_TOKEN") {
		t.Errorf("the panel should say how to configure web search:\n%s", v)
	}
}

// actionServer records admin load and unload calls and serves the list.
func actionServer(t *testing.T, fail bool) *[]string {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	useDeadServices(t)
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			calls = append(calls, r.URL.Path)
			mu.Unlock()
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "out of memory")
			}
			return
		}
		fmt.Fprint(w, `{"models":[{"id":"act-model","loaded":true},{"id":"hid-model"},{"id":"idle-model"}]}`)
	})
	return &calls
}

func TestModelsPanelLoadShowsLoadingAtOnceThenRefreshes(t *testing.T) {
	calls := actionServer(t, false)
	m := panelModel(t, 100, 30)
	m = selectRow(t, m, "idle-model")
	nm, cmd := m.Update(keyRunes("l"))
	m = nm.(model)
	if got := rowState(t, m, "idle-model"); got != "loading" {
		t.Errorf("state right after l = %q, want loading", got)
	}
	var sawDone, sawData bool
	for _, msg := range drain(cmd) {
		if _, ok := msg.(modelActionDoneMsg); ok {
			sawDone = true
			nm, cmd2 := m.Update(msg)
			m = nm.(model)
			for _, msg2 := range drain(cmd2) {
				if _, ok := msg2.(modelsDataMsg); ok {
					sawData = true
				}
			}
		}
	}
	if !sawDone || !sawData {
		t.Errorf("load should finish (%v) and refresh the list (%v)", sawDone, sawData)
	}
	if len(*calls) != 1 || (*calls)[0] != "/admin/api/models/idle-model/load" {
		t.Errorf("admin calls = %v", *calls)
	}
}

func TestModelsPanelUnloadActiveNeedsTwoPresses(t *testing.T) {
	calls := actionServer(t, false)
	m := panelModel(t, 100, 30) // the active model is selected
	m, _ = step(t, m, keyRunes("u"))
	if len(*calls) != 0 {
		t.Fatal("one u unloaded the active model")
	}
	if v := m.View(); !strings.Contains(v, "next answer will reload it") {
		t.Errorf("first u should warn:\n%s", v)
	}
	if f := m.footer(); !strings.Contains(f, "u confirm unload") || !strings.Contains(f, "any other key cancel") {
		t.Errorf("armed footer = %q", f)
	}
	// Any other key cancels, and does nothing else.
	m, _ = step(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if p := panelOf(t, m); p.armed != "" || p.rows()[p.sel].name != "act-model" {
		t.Errorf("another key should only cancel: armed=%q sel=%q", p.armed, p.rows()[p.sel].name)
	}
	m, _ = step(t, m, keyRunes("u"))
	step(t, m, keyRunes("u"))
	if len(*calls) != 1 || (*calls)[0] != "/admin/api/models/act-model/unload" {
		t.Errorf("two presses should unload once, calls = %v", *calls)
	}

	// Another model unloads on one press.
	m = selectRow(t, panelModel(t, 100, 30), "idle-model")
	*calls = nil
	d := panelData()
	d.chat[2].Loaded = true
	nm, _ := m.Update(modelsDataMsg{data: d})
	step(t, nm.(model), keyRunes("u"))
	if len(*calls) != 1 {
		t.Errorf("unload of an inactive model should take one press, calls = %v", *calls)
	}
}

func TestModelsPanelShowsActionErrorsInside(t *testing.T) {
	actionServer(t, true)
	m := selectRow(t, panelModel(t, 100, 30), "idle-model")
	m, _ = step(t, m, keyRunes("l"))
	if m.overlay == nil {
		t.Fatal("an error must not close the panel")
	}
	v := m.View()
	if !strings.Contains(v, "out of memory") {
		t.Errorf("the load error is not in the panel:\n%s", v)
	}
	if got := rowState(t, m, "idle-model"); got == "loading" {
		t.Error("a failed load still shows loading")
	}
}

func TestModelsPanelLoadUnsupportedWithoutAdmin(t *testing.T) {
	m := panelModel(t, 100, 30)
	d := panelData()
	d.admin = false
	for i := range d.chat {
		d.chat[i].Known = false
	}
	nm, _ := m.Update(modelsDataMsg{data: d})
	m = selectRow(t, nm.(model), "idle-model")
	m, msgs := step(t, m, keyRunes("l"))
	for _, msg := range msgs {
		if _, ok := msg.(modelActionDoneMsg); ok {
			t.Error("load ran against a server without the admin API")
		}
	}
	if v := m.View(); !strings.Contains(v, "not supported by this LLM server") {
		t.Errorf("view lacks the unsupported note:\n%s", v)
	}
}

func TestModelsPanelEnterAppliesAndRefreshRefetches(t *testing.T) {
	actionServer(t, false)
	m := selectRow(t, panelModel(t, 100, 30), "idle-model")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(model)
	msg := cmd()
	sel, ok := msg.(modelSelectedMsg)
	if !ok || sel.model != "idle-model" {
		t.Fatalf("enter = %#v, want modelSelectedMsg for idle-model", msg)
	}
	nm, _ = m.Update(msg)
	if got := nm.(model); got.ragModel != "idle-model" || got.overlay != nil || got.reasoning != "medium" {
		t.Errorf("after enter: model %q overlay %T reasoning %q", got.ragModel, got.overlay, got.reasoning)
	}

	m = panelModel(t, 100, 30)
	_, cmd = m.Update(keyRunes("r"))
	if _, ok := cmd().(modelsDataMsg); !ok {
		t.Error("r should refetch the models")
	}
}

func TestModelsPanelSanitizesHostileIDs(t *testing.T) {
	m := panelModel(t, 100, 30)
	d := panelData()
	d.chat = append(d.chat, chatModel{ID: "\x1b]0;t\x07m", Known: true, Size: "1 GB\x1b[2J"})
	nm, _ := m.Update(modelsDataMsg{data: d})
	v := nm.(model).View()
	if strings.Contains(v, "\x07") || strings.Contains(v, "]0;") || strings.Contains(v, "[2J") {
		t.Errorf("hostile id or size reached the view: %q", v)
	}
}

// The panel fits every terminal size, and at 80x24 every model row and every
// key hint of the selected row shows in full.
func TestModelsPanelLayout(t *testing.T) {
	noColor(t)
	for _, w := range []int{40, 80, 120} {
		for _, h := range []int{10, 24, 40} {
			m := panelModel(t, w, h)
			lines := strings.Split(m.View(), "\n")
			if len(lines) > h {
				t.Errorf("%dx%d: view has %d rows", w, h, len(lines))
			}
			for i, ln := range lines {
				if lipgloss.Width(ln) > w {
					t.Errorf("%dx%d: row %d is %d columns: %q", w, h, i, lipgloss.Width(ln), ln)
				}
			}
			checkBox(t, fmt.Sprintf("%dx%d", w, h), panelOf(t, m).View(w, h), w, h)
		}
	}
	// A short terminal keeps every row before the title, and says when rows
	// are scrolled off.
	if v := panelModel(t, 40, 17).View(); !strings.Contains(v, "web search") || strings.Contains(v, "MODELS") {
		t.Errorf("40x17 should drop the title to keep every row:\n%s", v)
	}
	if v := panelModel(t, 80, 10).View(); !strings.Contains(v, "more lines, up/down to scroll") {
		t.Errorf("80x10 should say rows are scrolled off:\n%s", v)
	}
	// A detail that does not fit drops whole parts, not half of one.
	if v := panelModel(t, 60, 24).View(); strings.Contains(v, "| ...") || strings.Contains(v, "|...") {
		t.Errorf("detail was cut inside a part:\n%s", v)
	}

	m := panelModel(t, 80, 24)
	view := m.View()
	for _, name := range []string{"act-model", "hid-model", "idle-model", "embedder", "reranker", "web search"} {
		if !strings.Contains(view, name) {
			t.Errorf("80x24 view lacks the %s row:\n%s", name, view)
		}
	}
	for _, name := range []string{"act-model", "hid-model", "embedder", "reranker", "web search"} {
		m = selectRow(t, m, name)
		f := m.footer()
		for _, b := range panelOf(t, m).hints(hint("esc/ctrl+c", "close")) {
			if want := b.Help().Key + " " + b.Help().Desc; !strings.Contains(f, want) {
				t.Errorf("80x24 footer on %s = %q, missing %q", name, f, want)
			}
		}
	}
}

func TestModelsPanelFooterListsTheKeys(t *testing.T) {
	m := selectRow(t, panelModel(t, 100, 30), "idle-model")
	f := m.footer()
	for _, want := range []string{"up/down move", "space hide", "l load", "enter use", "r refresh", "esc/ctrl+c close"} {
		if !strings.Contains(f, want) {
			t.Errorf("chat row footer %q lacks %q", f, want)
		}
	}
	m = selectRow(t, m, "reranker")
	if f := m.footer(); !strings.Contains(f, "space turn off") {
		t.Errorf("reranker footer = %q", f)
	}
}

// A load that ends after the panel closed prints its result instead.
func TestModelActionDoneAfterCloseIsPrinted(t *testing.T) {
	m := newKeyModel(t)
	_, cmd := m.Update(modelActionDoneMsg{id: "x", action: "load", err: errors.New("boom")})
	if out := printed(t, cmd); !strings.Contains(out, "boom") || !strings.Contains(out, "x") {
		t.Errorf("printed %q", out)
	}
}

// argsServer serves qwen-a, qwen-b, and gemma (loaded), and records load and
// unload calls.
func argsServer(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	useDeadServices(t)
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			calls = append(calls, r.URL.Path)
			mu.Unlock()
			return
		}
		fmt.Fprint(w, `{"models":[{"id":"qwen-a"},{"id":"qwen-b"},{"id":"gemma","loaded":true}]}`)
	})
	return &calls
}

// tuiSlash submits line in the TUI and returns the model after the command
// finished, with everything it printed.
func tuiSlash(t *testing.T, m model, line string) (model, string) {
	t.Helper()
	m.ta.SetValue(line)
	nm, cmd := m.submit()
	m = nm.(model)
	var out strings.Builder
	queue := drain(cmd)
	for len(queue) > 0 {
		msg := queue[0]
		queue = queue[1:]
		switch msg.(type) {
		case modelsArgsDoneMsg, prefsSavedMsg:
			nm, cmd := m.Update(msg)
			m = nm.(model)
			queue = append(queue, drain(cmd)...)
		default:
			fmt.Fprintln(&out, msg)
		}
	}
	return m, out.String()
}

func TestModelsSlashArgsInTheTUI(t *testing.T) {
	calls := argsServer(t)
	m := newKeyModel(t)
	m.ragModel = "gemma"

	cases := []struct {
		line, want string
		check      func(model) bool
	}{
		{"/models off reranker", "reranker off", func(m model) bool { return !m.prefs.Rerank && !loadPrefs().Rerank }},
		{"/models on reranker", "reranker on", func(m model) bool { return m.prefs.Rerank && loadPrefs().Rerank }},
		{"/models off qwen-a", "hidden", func(m model) bool { return m.prefs.isHidden("qwen-a") && loadPrefs().isHidden("qwen-a") }},
		{"/models on qwen-a", "shown", func(m model) bool { return !m.prefs.isHidden("qwen-a") }},
		{"/models off gem", "active model", func(m model) bool { return !m.prefs.isHidden("gemma") }},
		{"/models off qwen", "qwen-a, qwen-b", func(m model) bool { return len(m.prefs.Hidden) == 0 }},
		{"/models load nope", "no model named", nil},
		{"/models load qwen-b", "loaded qwen-b", func(model) bool { return len(*calls) == 1 && (*calls)[0] == "/admin/api/models/qwen-b/load" }},
		{"/models unload gemma", "next answer will reload it", func(model) bool { return len(*calls) == 2 }},
		{"/models unload reranker", "only chat models", nil},
		{"/models off embedder", "retrieval needs it", nil},
		{"/models frob x", "/models on|off|load|unload <name>", nil},
		{"/models off", "name a model", nil},
	}
	for _, c := range cases {
		var out string
		m, out = tuiSlash(t, m, c.line)
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: output %q lacks %q", c.line, out, c.want)
		}
		if c.check != nil && !c.check(m) {
			t.Errorf("%s: state check failed (prefs %+v)", c.line, m.prefs)
		}
	}

	t.Setenv("TAVILY_SETUP_TOKEN", "")
	if _, out := tuiSlash(t, m, "/models off web"); !strings.Contains(out, "TAVILY_SETUP_TOKEN") {
		t.Errorf("web without a token: %q", out)
	}
	t.Setenv("TAVILY_SETUP_TOKEN", "k")
	if m, out := tuiSlash(t, m, "/models off web"); !strings.Contains(out, "web search off") || m.prefs.Web {
		t.Errorf("web off: %q, prefs %+v", out, m.prefs)
	}

	m.ta.SetValue("/models")
	nm, cmd := m.submit()
	if _, ok := nm.(model).overlay.(modelsPanel); !ok {
		t.Fatalf("bare /models should open the panel, overlay = %T", nm.(model).overlay)
	}
	found := false
	for _, msg := range drain(cmd) {
		if _, ok := msg.(modelsDataMsg); ok {
			found = true
		}
	}
	if !found {
		t.Error("opening the panel should fetch the models")
	}
}

func TestModelsSlashArgsInThePlainREPL(t *testing.T) {
	calls := argsServer(t)
	isolateUserDirs(t)
	t.Setenv("OMLX_MODEL", "gemma")
	t.Setenv("TAVILY_SETUP_TOKEN", "k")
	run := func(arg string) string {
		t.Helper()
		var err error
		out := captureStdout(t, func() { err = replModels(arg) })
		if err != nil {
			out += err.Error()
		}
		return out
	}
	cases := []struct{ arg, want string }{
		{"off reranker", "reranker off"},
		{"off web", "web search off"},
		{"off qwen-b", "hidden"},
		{"off gemma", "active model"},
		{"off qwen", "qwen-a"},
		{"on zzz", "no model named"},
		{"load qwen-a", "loaded qwen-a"},
		{"unload gem", "unloaded gemma"},
		{"load web", "only chat models"},
		{"frob", "/models on|off|load|unload <name>"},
	}
	for _, c := range cases {
		if out := run(c.arg); !strings.Contains(out, c.want) {
			t.Errorf("/models %s: %q lacks %q", c.arg, out, c.want)
		}
	}
	if p := loadPrefs(); p.Rerank || p.Web || !p.isHidden("qwen-b") || p.isHidden("gemma") {
		t.Errorf("saved prefs = %+v", p)
	}
	if len(*calls) != 2 {
		t.Errorf("admin calls = %v, want a load and an unload", *calls)
	}

	noColor(t)
	out := run("")
	for _, want := range []string{"CHAT", "qwen-a", "qwen-b", "hidden", "gemma", "active", "RETRIEVAL", "embedder", "down", "reranker", "off", "WEB", "web search"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain /models list lacks %q:\n%s", want, out)
		}
	}
}

func TestModelPickerHidesHiddenModels(t *testing.T) {
	useDeadServices(t)
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"a"},{"id":"b"},{"id":"c"}]}`)
	})
	m := newKeyModel(t)
	m.ragModel = "a"
	m.prefs = defaultPrefs().withHidden("b", true)
	msg := m.openModelPickerCmd()().(openModelPickerMsg)
	if strings.Join(msg.models, ",") != "a,c" || msg.allHidden {
		t.Errorf("picker models = %v allHidden=%v, want [a c]", msg.models, msg.allHidden)
	}

	m.prefs = defaultPrefs().withHidden("b", true).withHidden("c", true)
	m.ragModel = "a"
	msg = m.openModelPickerCmd()().(openModelPickerMsg)
	if strings.Join(msg.models, ",") != "a" {
		t.Errorf("picker models = %v, want only the active one", msg.models)
	}
	m.prefs = m.prefs.withHidden("a", true) // hidden elsewhere, but still active
	msg = m.openModelPickerCmd()().(openModelPickerMsg)
	if strings.Join(msg.models, ",") != "a" || !msg.allHidden {
		t.Errorf("all hidden: models = %v allHidden=%v", msg.models, msg.allHidden)
	}
	nm, _ := m.Update(msg)
	if v := nm.(model).View(); !strings.Contains(v, "/models") {
		t.Errorf("an all-hidden picker should point to /models:\n%s", v)
	}
}

// Many toggles in a row start one save each. However the saves are scheduled,
// the file ends with the newest settings.
func TestRapidToggleSavesLeaveTheNewestSettings(t *testing.T) {
	isolateUserDirs(t)
	toggles := func(m model, n int) (model, []tea.Cmd, modelPrefs) {
		var cmds []tea.Cmd
		var last modelPrefs
		for i := 0; i < n; i++ {
			last = modelPrefs{Rerank: i%2 == 0, Web: i%3 == 0, Hidden: []string{fmt.Sprint("m", i)}}
			nm, cmd := m.Update(prefsChangedMsg{prefs: last})
			m = nm.(model)
			cmds = append(cmds, cmd)
		}
		return m, cmds, last
	}

	// The oldest save runs last.
	m, cmds, last := toggles(model{}, 40)
	for i := len(cmds) - 1; i >= 0; i-- {
		if msg, ok := cmds[i]().(prefsSavedMsg); !ok || msg.err != nil {
			t.Fatalf("save %d: %#v", i, msg)
		}
	}
	if got := loadPrefs(); !reflect.DeepEqual(got, last) {
		t.Fatalf("after saves in reverse order the file holds %+v, want the newest %+v", got, last)
	}

	// All at once.
	_, cmds, last = toggles(m, 40)
	var wg sync.WaitGroup
	for _, c := range cmds {
		wg.Add(1)
		go func() { defer wg.Done(); c() }()
	}
	wg.Wait()
	if got := loadPrefs(); !reflect.DeepEqual(got, last) {
		t.Fatalf("after concurrent saves the file holds %+v, want the newest %+v", got, last)
	}
}

// A panel toggle made while a "/models off <name>" command is in flight
// survives the command's result, in memory and on disk, and the panel keeps
// the command's change for its own next toggle.
func TestModelsArgsKeepsAToggleMadeWhileInFlight(t *testing.T) {
	argsServer(t)
	m := newKeyModel(t)
	m.ragModel = "gemma"

	// The command runs (its network work is done) but its result is not yet in.
	m.ta.SetValue("/models off qwen-a")
	nm, cmd := m.submit()
	m = nm.(model)
	var done tea.Msg
	for _, msg := range drain(cmd) {
		if _, ok := msg.(modelsArgsDoneMsg); ok {
			done = msg
		}
	}
	if done == nil {
		t.Fatal("the command produced no result")
	}

	// Meanwhile the panel turns the reranker off.
	m.overlay = newModelsPanel(m.prefs, m.currentModel())
	nm, _ = m.Update(modelsDataMsg{data: panelData()})
	m = selectRow(t, nm.(model), "reranker")
	m, _ = step(t, m, keySpace)
	if m.prefs.Rerank {
		t.Fatal("the panel toggle did not apply")
	}

	// The command's result lands.
	nm, cmd = m.Update(done)
	m = nm.(model)
	for _, msg := range drain(cmd) {
		if _, ok := msg.(prefsSavedMsg); ok {
			nm, _ := m.Update(msg)
			m = nm.(model)
		}
	}
	check := func(when string, p modelPrefs) {
		t.Helper()
		if p.Rerank || !p.isHidden("qwen-a") {
			t.Errorf("%s: prefs = %+v, want the reranker off and qwen-a hidden", when, p)
		}
	}
	check("in memory", m.prefs)
	check("on disk", loadPrefs())
	check("in the panel", panelOf(t, m).prefs)

	// The panel's next toggle keeps the command's change too.
	m = selectRow(t, m, "web search")
	m, _ = step(t, m, keySpace)
	if p := loadPrefs(); p.Web || !p.isHidden("qwen-a") || p.Rerank {
		t.Errorf("after the next toggle, on disk = %+v", p)
	}
}

// With OMLX_MODEL unset and no model picked, a turn uses the first model the
// server lists. The status line, the panel's active row, the hide guard, and
// the unload confirmation follow that model once the list has loaded, and
// before that nothing is protected.
func TestActiveModelIsTheFirstListedModel(t *testing.T) {
	var mu sync.Mutex
	var unloads []string
	useDeadServices(t)
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"b-model"},{"id":"a-model"}]}`)
		case r.Method == http.MethodPost:
			mu.Lock()
			unloads = append(unloads, r.URL.Path)
			mu.Unlock()
		default:
			fmt.Fprint(w, `{"models":[{"id":"a-model","loaded":true},{"id":"b-model","loaded":true}]}`)
		}
	})
	t.Setenv("OMLX_MODEL", "")
	m := newKeyModel(t)
	m.cfg.DefaultModel = "a-model"
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = nm.(model)
	openPanel := func(m model) model {
		t.Helper()
		m, _ = tuiSlash(t, m, "/models")
		nm, _ := m.Update(fetchModelsCmd())
		return nm.(model)
	}

	// Before the list loads: the configured default shows, nothing is active.
	if s := m.statusLine(); !strings.Contains(s, "a-model") {
		t.Errorf("status before the list loads = %q, want the configured default", s)
	}
	if got := m.activeModel(); got != "" {
		t.Errorf("activeModel before the list loads = %q, want none", got)
	}
	pm, _ := tuiSlash(t, m, "/models")
	if p := panelOf(t, pm); p.active != "" {
		t.Errorf("the panel opened before the list loads protects %q", p.active)
	}

	// The list loads.
	msg := resolveModelCmd()
	nm, _ = m.Update(msg)
	m = nm.(model)
	if got := m.activeModel(); got != "b-model" {
		t.Fatalf("activeModel = %q, want b-model, the first listed", got)
	}
	if s := m.statusLine(); !strings.Contains(s, "b-model") || strings.Contains(s, "a-model") {
		t.Errorf("status = %q, want b-model", s)
	}
	pm = openPanel(m)
	if st := rowState(t, pm, "b-model"); !strings.HasPrefix(st, "active") {
		t.Errorf("b-model state = %q, want active", st)
	}
	if st := rowState(t, pm, "a-model"); strings.Contains(st, "active") {
		t.Errorf("a-model state = %q, want not active", st)
	}
	pm = selectRow(t, pm, "b-model")
	pm, _ = step(t, pm, keySpace)
	if pm.prefs.isHidden("b-model") {
		t.Error("the panel hid the model a turn uses")
	}
	pm = selectRow(t, pm, "a-model")
	pm, _ = step(t, pm, keySpace)
	if !pm.prefs.isHidden("a-model") {
		t.Error("the panel refused to hide the configured default, which is not in use")
	}
	pm = selectRow(t, pm, "b-model")
	pm, _ = step(t, pm, keyRunes("u"))
	if v := pm.View(); len(unloads) != 0 || !strings.Contains(v, "press u again") {
		t.Errorf("one u on b-model: unloads %v, view:\n%s", unloads, v)
	}

	m, out := tuiSlash(t, m, "/models off b-model")
	if !strings.Contains(out, "active model") || m.prefs.isHidden("b-model") {
		t.Errorf("/models off b-model: %q, prefs %+v", out, m.prefs)
	}

	// A resolved model is kept for the session; a pick overrides it.
	nm, _ = m.Update(modelResolvedMsg("c-model"))
	if got := nm.(model).activeModel(); got != "b-model" {
		t.Errorf("a second resolution changed the active model to %q", got)
	}
	m.ragModel = "a-model"
	if got := m.activeModel(); got != "a-model" {
		t.Errorf("activeModel with a pick = %q", got)
	}
}

// With the LLM server down at startup and up by the time /models opens, the
// panel's list resolves the model a turn uses: it is marked active, and one u
// on it only asks for confirmation.
func TestModelsPanelResolvesTheActiveModelWhenTheListLoadsLate(t *testing.T) {
	useDeadServices(t)
	t.Setenv("OMLX_MODEL", "")
	m := newKeyModel(t)
	m.cfg.DefaultModel = "a-model"
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = nm.(model)
	if msg := resolveModelCmd(); msg != nil {
		t.Fatalf("resolution with the server down = %#v, want nothing", msg)
	}

	var mu sync.Mutex
	var unloads []string
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"b-model"},{"id":"a-model"}]}`)
		case r.Method == http.MethodPost:
			mu.Lock()
			unloads = append(unloads, r.URL.Path)
			mu.Unlock()
		default:
			fmt.Fprint(w, `{"models":[{"id":"a-model","loaded":true},{"id":"b-model","loaded":true}]}`)
		}
	})
	m, _ = tuiSlash(t, m, "/models")
	nm, _ = m.Update(fetchModelsCmd())
	m = nm.(model)
	if st := rowState(t, m, "b-model"); !strings.HasPrefix(st, "active") {
		t.Errorf("b-model state = %q, want active once the list loads", st)
	}
	if got := m.activeModel(); got != "b-model" {
		t.Errorf("activeModel = %q, want b-model", got)
	}
	m = selectRow(t, m, "b-model")
	m, _ = step(t, m, keyRunes("u"))
	mu.Lock()
	n := len(unloads)
	mu.Unlock()
	if n != 0 || !strings.Contains(m.View(), "press u again") {
		t.Errorf("one u on the model a turn uses: %d unloads, view:\n%s", n, m.View())
	}
}

func TestSetModelSwitchRag(t *testing.T) {
	p := modelPrefs{Rag: true}
	got, _, err := setModelSwitch(p, rowRag, "", false, "active", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rag {
		t.Error("rag should be off")
	}
	got, _, err = setModelSwitch(got, rowRag, "", true, "active", true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Rag {
		t.Error("rag should be on")
	}
}

func TestRunModelsArgsRagKind(t *testing.T) {
	_, sw, err := runModelsArgs("off", "rag", "active")
	if err != nil {
		t.Fatal(err)
	}
	if sw == nil || sw.kind != rowRag || sw.on {
		t.Errorf("switch = %+v, want rowRag off", sw)
	}
}

// webPanel opens the /models panel on panelData with the web switch and the
// active provider set, for exercising the web row's provider reflection.
func webPanel(t *testing.T, provider string, web bool) model {
	t.Helper()
	m := newKeyModel(t)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(model)
	m.ragModel = "act-model"
	m.prefs = defaultPrefs().withHidden("hid-model", true)
	m.prefs.Web = web
	m.overlay = newModelsPanel(m.prefs, m.currentModel())
	d := panelData()
	d.webProvider = provider
	nm, _ = m.Update(modelsDataMsg{data: d})
	return nm.(model)
}

// The panel web row keeps the colored state word (on/off/not configured) and
// names the active provider in the detail column; with no provider it says how
// to configure one.
func TestModelsPanelWebProviderStates(t *testing.T) {
	isolateUserDirs(t)
	cases := []struct {
		provider   string
		web        bool
		wantState  string
		wantDetail string
	}{
		{webProviderTavily, true, "on", "tavily"},
		{webProviderTavily, false, "off", "tavily"},
		{webProviderDuckDuckGo, true, "on", "duckduckgo fallback"},
		{webProviderDuckDuckGo, false, "off", "duckduckgo fallback"},
		{webProviderNone, true, "not configured", "or DuckDuckGo"},
	}
	for _, c := range cases {
		m := webPanel(t, c.provider, c.web)
		if got := rowState(t, m, "web search"); got != c.wantState {
			t.Errorf("provider %q web=%v: state = %q, want %q", c.provider, c.web, got, c.wantState)
		}
		if v := m.View(); !strings.Contains(v, c.wantDetail) {
			t.Errorf("provider %q web=%v: view lacks %q:\n%s", c.provider, c.web, c.wantDetail, v)
		}
	}
}

// The keyless DuckDuckGo fallback makes web search available, so the panel
// toggles it (the on/off action is no longer gated on a Tavily token).
func TestModelsPanelWebDDGFallbackToggles(t *testing.T) {
	isolateUserDirs(t)
	m := webPanel(t, webProviderDuckDuckGo, true)
	m = selectRow(t, m, "web search")
	m, _ = step(t, m, keySpace)
	if m.prefs.Web {
		t.Error("space on an available DDG web search should turn it off")
	}
	if got := rowState(t, m, "web search"); got != "off" {
		t.Errorf("after toggle: state = %q, want off", got)
	}
	if v := m.View(); !strings.Contains(v, "duckduckgo fallback") {
		t.Errorf("view should name the DDG provider:\n%s", v)
	}
}
