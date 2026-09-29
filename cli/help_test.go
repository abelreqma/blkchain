package main

import (
	"bytes"
	"errors"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"blkchain/cli/internal/ragconfig"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// wordingDescs is the shared wording table (one line per command). The CLI
// usage, per-command help, and shell completion must use these lines verbatim.
var wordingDescs = map[string]string{
	"ask":        "answer a question, with cited sources",
	"search":     "find the most relevant source passages for a query",
	"open":       "open a cited source in your pager or editor",
	"add":        "add your own files, folders, or a web page",
	"up":         "start the local services",
	"down":       "stop the local services",
	"status":     "show whether each local service is running",
	"health":     "check qdrant, embed_server, and the LLM",
	"doctor":     "check the whole setup and say what to fix",
	"models":     "check each model's readiness and speed",
	"logs":       "show the embed_server log; -f follows it",
	"hermes":     "run one Hermes agent turn with the knowledge base",
	"gateway":    "set up and start the Hermes gateway for agent mode",
	"mcp":        "serve the knowledge base to Hermes over MCP (stdio)",
	"install":    "put blk on your PATH (run once, from the project)",
	"completion": "print a bash or zsh completion script",
	"version":    "show version and build info",
	"help":       "show help for blk or for one command",
}

var wordingGroups = [][]string{
	{"ask", "search", "open", "add"},
	{"up", "down", "status", "health", "doctor", "models", "logs"},
	{"hermes", "gateway", "mcp"},
	{"install", "completion", "version", "help"},
}

var wordingGroupTitles = []string{"ASK AND SEARCH", "SERVICES", "AGENT (HERMES)", "SETUP"}

var wordingEnv = []string{
	"BLKCHAIN_ROOT", "BLKCHAIN_COLLECTION", "BLKCHAIN_TIMEOUT_SECONDS", "QDRANT_GRPC_URL",
	"OMLX_BASE_URL", "OMLX_MODEL", "OMLX_API_KEY", "TAVILY_SETUP_TOKEN",
	"BLK_THEME", "BLK_ACCENT", "BLK_REDUCE_MOTION", "NO_COLOR",
}

func assertMaxWidth(t *testing.T, label, s string, max int) {
	t.Helper()
	for i, ln := range strings.Split(s, "\n") {
		if n := utf8.RuneCountInString(ln); n > max {
			t.Errorf("%s line %d is %d columns, max %d: %q", label, i+1, n, max, ln)
		}
	}
}

func assertASCII(t *testing.T, label, s string) {
	t.Helper()
	for _, r := range s {
		if r > 0x7e || (r < 0x20 && r != '\n') {
			t.Errorf("%s holds non-ASCII or control rune %q", label, r)
			return
		}
	}
}

func lineWith(s, sub string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			return ln
		}
	}
	return ""
}

func TestEveryCommandHasCompleteHelpEntry(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commandSpecs() {
		seen[c.name] = true
		if c.run == nil {
			t.Errorf("%s has no run function", c.name)
		}
		if c.desc == "" || c.long == "" {
			t.Errorf("%s needs a description and a DESCRIPTION text", c.name)
		}
		if n := len(c.examples); n < 2 || n > 3 {
			t.Errorf("%s has %d examples, want 2 or 3", c.name, n)
		}
		for _, ex := range c.examples {
			if !strings.HasPrefix(ex, "blk ") && !strings.Contains(ex, "blk ") {
				t.Errorf("%s example %q does not show a blk invocation", c.name, ex)
			}
		}
		if c.group != "" && !containsStr(wordingGroupTitles, c.group) {
			t.Errorf("%s has unknown group %q", c.name, c.group)
		}
		if sentences := strings.Count(c.long, ". ") + 1; sentences < 2 || sentences > 4 {
			t.Errorf("%s DESCRIPTION has %d sentences, want 2 to 4", c.name, sentences)
		}
	}
	for name := range wordingDescs {
		if !seen[name] {
			t.Errorf("wording command %q has no spec", name)
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestSpecsUseTheSharedWording(t *testing.T) {
	for name, want := range wordingDescs {
		c, ok := lookupCommand(name)
		if !ok {
			t.Fatalf("no spec for %q", name)
		}
		if c.desc != want {
			t.Errorf("%s desc = %q, want %q", name, c.desc, want)
		}
	}
	for gi, names := range wordingGroups {
		for _, name := range names {
			c, _ := lookupCommand(name)
			if c.group != wordingGroupTitles[gi] {
				t.Errorf("%s group = %q, want %q", name, c.group, wordingGroupTitles[gi])
			}
		}
	}
}

// Dispatch is table driven, so a command cannot be added without a spec. This
// guards a return to a hand-written switch: every string case in dispatch must
// resolve to a spec.
func TestDispatchCasesAllHaveSpecs(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "dispatch" {
			continue
		}
		found = true
		ast.Inspect(fd, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					name := strings.Trim(lit.Value, `"`)
					if _, ok := lookupCommand(name); !ok {
						t.Errorf("dispatch handles %q but it has no help spec", name)
					}
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("dispatch function not found in main.go")
	}
}

func TestUsageLayout(t *testing.T) {
	t.Setenv("OMLX_API_KEY", "sekret-llm-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "sekret-tavily-token")
	out := renderUsage(80)
	assertMaxWidth(t, "usage", out, 80)
	assertASCII(t, "usage", out)

	// One heading level: the groups are top-level sections, in order, and
	// there is no COMMANDS wrapper or global FLAGS section.
	order := append(append([]string{"USAGE"}, wordingGroupTitles...), "EXAMPLES", "ENVIRONMENT")
	prev := -1
	for _, h := range order {
		i := strings.Index(out, "\n "+h+"\n")
		if i < 0 {
			t.Fatalf("usage lacks the %q section:\n%s", h, out)
		}
		if i < prev {
			t.Errorf("section %q is out of order", h)
		}
		prev = i
	}
	for _, gone := range []string{"COMMANDS", "\n FLAGS\n", "knowledge-base client"} {
		if strings.Contains(out, gone) {
			t.Errorf("usage still has %q", gone)
		}
	}
	for _, want := range []string{
		"start the interactive session",
		"   blk <command> [flags]  run one command",
		"Add --json to ask, search, or models for machine-readable output.",
		"flags go before or after the query",
		`Run "blk help <command>" for its flags`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
	if strings.Contains(out, "sekret") {
		t.Error("usage must never print a secret value")
	}

	// The synopsis rows share the description column with the command rows.
	usageCol := strings.Index(lineWith(out, "run one command"), "run one command")

	// The title names the tool with the README's own description.
	title := strings.Split(out, "\n")[0]
	if !strings.HasPrefix(title, " blk  "+usageTagline) || len(usageTagline) >= 45 {
		t.Errorf("title line = %q, tagline %q", title, usageTagline)
	}

	// Each command row shows its argument signature, and every description
	// starts at the same column, whatever the group.
	descCol := -1
	for gi, names := range wordingGroups {
		sec := section(out, wordingGroupTitles[gi], "")
		for _, name := range names {
			c, _ := lookupCommand(name)
			sig := strings.TrimSpace(name + " " + c.args)
			row := lineWith(sec, sig+" ")
			if !strings.HasPrefix(row, "   "+sig+" ") {
				t.Errorf("row for %q is %q, want it to start with its signature %q", name, row, sig)
				continue
			}
			first := strings.Fields(c.desc)[0]
			col := strings.Index(row[len(sig)+3:], first) + len(sig) + 3
			if descCol < 0 {
				descCol = col
			}
			if col != descCol {
				t.Errorf("%s description starts at column %d, want %d", name, col, descCol)
			}
			if !strings.Contains(collapse(sec), c.desc) {
				t.Errorf("%s description is not verbatim: %q", name, row)
			}
		}
	}
	if usageCol != descCol {
		t.Errorf("USAGE descriptions start at column %d, commands at %d", usageCol, descCol)
	}
	// A wrapped description (the ask row at 60 columns) continues under the
	// description column, which does not depend on the width.
	lines := strings.Split(section(renderUsage(60), "ASK AND SEARCH", ""), "\n")
	wrapped := false
	for i, ln := range lines {
		if strings.HasPrefix(ln, "   ask ") && i+1 < len(lines) {
			cont := lines[i+1]
			wrapped = strings.HasPrefix(cont, strings.Repeat(" ", descCol))
			if !wrapped || cont[descCol] == ' ' {
				t.Errorf("ask continuation at 60 %q does not start at column %d", cont, descCol)
			}
		}
	}
	if !wrapped {
		t.Error("the ask row no longer wraps at 60 columns; pick another wrapped row")
	}

	// Examples: three or four prompted lines covering start-up, ask, and search with a flag.
	var cmds []string
	for _, ln := range strings.Split(section(out, "EXAMPLES", "ENVIRONMENT"), "\n") {
		if strings.HasPrefix(ln, "   $ blk ") {
			cmds = append(cmds, strings.TrimPrefix(ln, "   $ "))
		}
	}
	if len(cmds) != len(usageExamples) || len(cmds) < 3 || len(cmds) > 4 {
		t.Errorf("usage has %d prompted examples, want all of %v", len(cmds), usageExamples)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"blk ask ", "blk search ", "--top-k", "blk up"} {
		if !strings.Contains(joined, want) {
			t.Errorf("examples lack %q:\n%s", want, joined)
		}
	}

	// The short environment list names its variables and points to the full list.
	env := section(out, "ENVIRONMENT", "")
	for _, name := range usageEnvShort {
		if row := lineWith(env, name); len(strings.Fields(row)) < 3 {
			t.Errorf("ENVIRONMENT row for %s has no meaning: %q", name, row)
		}
	}
	if n := len(usageEnvShort); n < 4 || n > 5 {
		t.Errorf("short environment list has %d names, want 4 or 5", n)
	}
	total := 0
	for _, g := range usageEnv() {
		total += len(g.rows)
	}
	if want := `"blk help env" for all ` + strconv.Itoa(total) + " variables"; !strings.Contains(out, want) {
		t.Errorf("usage lacks %q", want)
	}
}

// section returns the text from the heading line start up to the next heading
// (end, or any top-level heading when end is empty).
func section(s, start, end string) string {
	i := strings.Index(s, "\n "+start+"\n")
	if i < 0 {
		return ""
	}
	rest := s[i+1:]
	if end != "" {
		if j := strings.Index(rest, "\n "+end+"\n"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	if j := strings.Index(rest, "\n\n "); j >= 0 {
		return rest[:j]
	}
	return rest
}

func TestUsageIsAtMost50Lines(t *testing.T) {
	out := renderUsage(80)
	if n := strings.Count(out, "\n"); n > 50 {
		t.Errorf("usage is %d lines at 80 columns, want at most 50:\n%s", n, out)
	}
}

// At 60, 80, and 100 columns nothing runs past the width and everything the
// page names is present: each command signature and example unbroken on one
// line, and each short-list variable.
func TestUsageContentAtEveryWidth(t *testing.T) {
	for _, w := range []int{60, 80, 100} {
		out := renderUsage(w)
		assertMaxWidth(t, "usage", out, w)
		for _, c := range commandSpecs() {
			if c.group == "" {
				continue
			}
			sig := strings.TrimSpace(c.name + " " + c.args)
			if !strings.HasPrefix(lineWith(out, "   "+sig+" "), "   "+sig+" ") {
				t.Errorf("width %d: no row starts with %q", w, sig)
			}
			if !strings.Contains(collapse(out), c.desc) {
				t.Errorf("width %d: %s description is missing", w, c.name)
			}
		}
		for _, ex := range usageExamples {
			if lineWith(out, "   $ "+ex) == "" {
				t.Errorf("width %d: example %q is not on one line", w, ex)
			}
		}
		for _, name := range usageEnvShort {
			if lineWith(out, "   "+name+" ") == "" {
				t.Errorf("width %d: usage lacks %s", w, name)
			}
		}
	}
}

// At 80 columns every listed command row is one line: its whole description
// sits on the row and no continuation line follows it.
func TestUsageCommandRowsAreOneLineAt80(t *testing.T) {
	out := renderUsage(80)
	lines := strings.Split(out, "\n")
	for _, c := range commandSpecs() {
		if c.group == "" {
			continue
		}
		sig := strings.TrimSpace(c.name + " " + c.args)
		for i, ln := range lines {
			if !strings.HasPrefix(ln, "   "+sig+" ") {
				continue
			}
			if !strings.HasSuffix(ln, c.desc) {
				t.Errorf("%s row does not hold its whole description: %q", c.name, ln)
			}
			if next := lines[i+1]; strings.HasPrefix(next, "    ") {
				t.Errorf("%s row wraps onto %q", c.name, next)
			}
		}
	}
}

// The closing lines highlight the command text in them the way the examples
// do, and the rest stays muted.
func TestUsageClosingLinesHighlightCommands(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })
	out := renderUsage(80)
	for _, want := range []string{
		Meta.Render("Add ") + Flag.Render("--json") + Meta.Render(" to ask, search, or models for machine-readable output."),
		Meta.Render(`Run "`) + styleWords("blk help <command>") + Meta.Render(`" for its flags, or "`) + styleWords("blk help env"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage closing lines lack %q", want)
		}
	}
}

func TestUsageFitsNarrowTerminals(t *testing.T) {
	out := renderUsage(40)
	assertMaxWidth(t, "usage", out, 40)
	for _, name := range []string{"ask", "models", "OMLX_BASE_URL", "help"} {
		if !strings.Contains(out, name) {
			t.Errorf("width 40: usage lost %q", name)
		}
	}
}

// With color off (NO_COLOR, TERM=dumb, or a pipe) no help surface carries an
// escape sequence, and the layout is the same text.
func TestHelpHasNoEscapesWithColorOff(t *testing.T) {
	noColor(t)
	got := map[string]string{"usage": renderUsage(80), "env": renderEnvHelp(80)}
	for _, c := range commandSpecs() {
		got[c.name] = renderCommandHelp(c, 80)
	}
	for name, s := range got {
		if strings.ContainsRune(s, 0x1b) {
			t.Errorf("%s help holds an escape sequence with color off", name)
		}
	}
}

// blk help env (and blk help environment) is a help topic: it lists every
// variable in its group, but it is not a command, so dispatch, the command
// list, and shell completion of commands do not know it.
func TestHelpEnvTopic(t *testing.T) {
	t.Setenv("OMLX_API_KEY", "sekret-llm-key")
	want := renderEnvHelp(terminalWidth())
	for _, arg := range []string{"env", "environment"} {
		var err error
		out := captureStdout(t, func() { err = runHelp([]string{arg}) })
		if err != nil || exitCode(err) != 0 || out != want {
			t.Errorf("blk help %s: err = %v, output differs from the env topic", arg, err)
		}
	}
	for _, w := range []int{60, 80, 100} {
		out := renderEnvHelp(w)
		assertMaxWidth(t, "env help", out, w)
		assertASCII(t, "env help", out)
		if strings.Contains(out, "sekret") {
			t.Error("env help must never print a secret value")
		}
		prev := -1
		for _, g := range usageEnv() {
			i := strings.Index(out, "\n "+g.title+"\n")
			if i < prev {
				t.Errorf("width %d: env help lacks the %q section or has it out of order", w, g.title)
			}
			prev = i
			for _, r := range g.rows {
				if row := lineWith(out, "   "+r.name+" "); row == "" {
					t.Errorf("width %d: env help lacks %s", w, r.name)
				}
			}
		}
		for _, env := range wordingEnv {
			if lineWith(out, env) == "" {
				t.Errorf("width %d: env help lacks %s", w, env)
			}
		}
	}
	out := renderEnvHelp(80)
	if last := strings.TrimSpace(lastLine(out)); last != `Run "blk help" to see all commands.` {
		t.Errorf("env help closing line = %q", last)
	}
	for _, name := range []string{"env", "environment"} {
		if _, ok := lookupCommand(name); ok {
			t.Errorf("%q must be a help topic, not a command", name)
		}
		if containsStr(commandNames(), name) {
			t.Errorf("%q is in the command list", name)
		}
		re := regexp.MustCompile(`\b` + name + `\b`)
		if re.MatchString(bashCompletion()) || re.MatchString(zshCompletion()) {
			t.Errorf("shell completion offers %q", name)
		}
		var err error
		captureBoth(t, func() { err = dispatch(name, nil) })
		if exitCode(err) != 2 {
			t.Errorf("blk %s: exit %d, want the unknown-command 2", name, exitCode(err))
		}
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func TestEnvHelpDefaultsMatchCode(t *testing.T) {
	for _, k := range []string{"QDRANT_GRPC_URL", "BLKCHAIN_TIMEOUT_SECONDS"} {
		t.Setenv(k, "")
	}
	cfg := ragconfig.Load()
	out := renderEnvHelp(80)
	for _, want := range []string{
		defaultOMLXBaseURL,
		defaultCollection,
		cfg.QdrantGRPCURL,
		"default " + strconv.Itoa(cfg.RequestTimeoutSeconds),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("env help lacks the code default %q", want)
		}
	}
}

func TestTokenizeExample(t *testing.T) {
	type tk = exTok
	cases := []struct {
		in   string
		want []exTok
	}{
		{`blk search "JWT none algorithm" --top-k 10`, []exTok{
			tk{"blk", exBlk}, tk{"search", exSub}, tk{`"JWT none algorithm"`, exStr},
			tk{"--top-k", exFlag}, tk{"10", exValue}}},
		{`blk ask --json "what is IDOR?"`, []exTok{
			tk{"blk", exBlk}, tk{"ask", exSub}, tk{"--json", exFlag}, tk{`"what is IDOR?"`, exStr}}},
		{"blk logs embed_server -n 100", []exTok{
			tk{"blk", exBlk}, tk{"logs", exSub}, tk{"embed_server", exOther}, tk{"-n", exFlag}, tk{"100", exValue}}},
		{"blk logs -f", []exTok{tk{"blk", exBlk}, tk{"logs", exSub}, tk{"-f", exFlag}}},
		{"blk search --help", []exTok{tk{"blk", exBlk}, tk{"search", exSub}, tk{"--help", exFlag}}},
		{"blk up && blk doctor", []exTok{
			tk{"blk", exBlk}, tk{"up", exSub}, tk{"&&", exOther}, tk{"blk", exBlk}, tk{"doctor", exSub}}},
		{"blk <command> [flags]", []exTok{tk{"blk", exBlk}, tk{"<command>", exPlace}, tk{"[flags]", exPlace}}},
		{"echo 'source <(blk completion bash)' >> ~/.bashrc", []exTok{
			tk{"echo", exOther}, tk{"'source <(blk completion bash)'", exStr}, tk{">>", exOther}, tk{"~/.bashrc", exOther}}},
		{`blk ask "unterminated`, []exTok{tk{"blk", exBlk}, tk{"ask", exSub}, tk{`"unterminated`, exStr}}},
		{"  blk   up  ", []exTok{tk{"blk", exBlk}, tk{"up", exSub}}},
		{"", nil},
	}
	for _, tc := range cases {
		if got := tokenizeExample(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("tokenizeExample(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// An example laid out at any width keeps its text: joined back, the lines give
// the prompt and the example, and none runs past the width.
func TestExampleLinesKeepTheText(t *testing.T) {
	noColor(t)
	for _, c := range commandSpecs() {
		for _, ex := range c.examples {
			for _, w := range []int{30, 40, 80} {
				lines := exampleLines(ex, 3, w)
				assertMaxWidth(t, "example", strings.Join(lines, "\n"), w)
				if got := collapse(strings.Join(lines, " ")); got != collapse("$ "+ex) && w >= 40 {
					t.Errorf("width %d: example %q laid out as %q", w, ex, got)
				}
			}
		}
	}
}

func TestCommandHelpLayout(t *testing.T) {
	for _, c := range commandSpecs() {
		out := renderCommandHelp(c, 80)
		assertMaxWidth(t, c.name+" help", out, 80)
		assertASCII(t, c.name+" help", out)

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		wantTitle := strings.TrimSpace("blk " + c.name + " " + c.args)
		if got := strings.TrimSpace(lines[0]); got != wantTitle {
			t.Errorf("%s title = %q, want %q", c.name, got, wantTitle)
		}
		if got := strings.TrimSpace(lines[1]); got != c.desc {
			t.Errorf("%s second line = %q, want the description %q", c.name, got, c.desc)
		}
		if last := lines[len(lines)-1]; strings.TrimSpace(last) != `Run "blk help" to see all commands.` {
			t.Errorf("%s closing line = %q", c.name, last)
		}
		idx := func(h string) int { return strings.Index(out, "\n "+h+"\n") }
		if idx("DESCRIPTION") < 0 || idx("EXAMPLES") < 0 || idx("DESCRIPTION") > idx("EXAMPLES") {
			t.Errorf("%s help sections missing or out of order:\n%s", c.name, out)
		}
		hasFlags := c.flags != nil && len(flagRows(commandFlagSet(c))) > 0
		if hasFlags != (idx("FLAGS") >= 0) {
			t.Errorf("%s FLAGS section present = %v, want %v", c.name, idx("FLAGS") >= 0, hasFlags)
		}
		if hasFlags && (idx("FLAGS") < idx("DESCRIPTION") || idx("FLAGS") > idx("EXAMPLES")) {
			t.Errorf("%s FLAGS is out of order", c.name)
		}
		for _, ex := range c.examples {
			if lineWith(out, "   $ "+ex) == "" {
				t.Errorf("%s help lacks the prompted example %q", c.name, ex)
			}
		}
	}
}

func TestCommandHelpFlagRows(t *testing.T) {
	c, _ := lookupCommand("search")
	out := renderCommandHelp(c, 80)
	for _, want := range []string{"--top-k N", "--source NAME", "--type TYPE", "--filter KEY=VALUE", "--json"} {
		if !strings.Contains(out, want) {
			t.Errorf("search help lacks %q:\n%s", want, out)
		}
	}
	if row := lineWith(out, "--top-k N"); !strings.Contains(row, "default 5") {
		t.Errorf("--top-k row lacks its default: %q", row)
	}
	// The default shows only when meaningful: logs -n has one, -f does not.
	l, _ := lookupCommand("logs")
	lout := renderCommandHelp(l, 80)
	if row := lineWith(lout, "-n N"); !strings.Contains(row, "default 40") {
		t.Errorf("logs -n row lacks its default: %q", row)
	}
	if row := lineWith(lout, "-f "); strings.Contains(row, "default") {
		t.Errorf("logs -f is a bool and must not show a default: %q", row)
	}
	// Flags are not shown twice with different meanings: ask and add each own theirs.
	a, _ := lookupCommand("add")
	if row := lineWith(renderCommandHelp(a, 80), "--type"); !strings.Contains(row, "md") {
		t.Errorf("add --type row should name the md/txt/pdf values: %q", row)
	}
}

func TestCommandHelpWrapsToNarrowWidth(t *testing.T) {
	for _, c := range commandSpecs() {
		assertMaxWidth(t, c.name+" help at 40", renderCommandHelp(c, 40), 40)
	}
}

func TestHelpFlagsPrintHelpToStdoutAndExitZero(t *testing.T) {
	for _, c := range commandSpecs() {
		want := renderCommandHelp(c, 80)
		for _, flagArg := range []string{"-h", "--help"} {
			var err error
			stdout, stderr := captureBoth(t, func() { err = dispatch(c.name, []string{flagArg}) })
			if err != nil || exitCode(err) != 0 {
				t.Errorf("blk %s %s: err = %v, exit %d, want none and 0", c.name, flagArg, err, exitCode(err))
			}
			if stdout != want {
				t.Errorf("blk %s %s stdout differs from the help text:\n%s", c.name, flagArg, stdout)
			}
			if stderr != "" || strings.Contains(stdout, "help requested") || strings.Contains(stdout, "Usage of") {
				t.Errorf("blk %s %s wrote an error or the raw flag dump: stderr %q", c.name, flagArg, stderr)
			}
		}
		var err error
		stdout := captureStdout(t, func() { err = runHelp([]string{c.name}) })
		if err != nil || stdout != want {
			t.Errorf("blk help %s: err = %v, stdout differs", c.name, err)
		}
	}
}

func TestFlagSetHelpIsHandledInsideTheCommand(t *testing.T) {
	// -h after other flags and the query still prints the help and is not an error line.
	var err error
	stdout, stderr := captureBoth(t, func() { err = runSearch([]string{"--top-k", "3", "ssrf", "-h"}) })
	if !errors.Is(err, flag.ErrHelp) || exitCode(err) != 0 {
		t.Errorf("err = %v, exit %d, want flag.ErrHelp and exit 0", err, exitCode(err))
	}
	if !strings.Contains(stdout, "EXAMPLES") || stderr != "" {
		t.Errorf("stdout %q stderr %q", stdout, stderr)
	}
	var buf bytes.Buffer
	reportError(&buf, err)
	if buf.Len() != 0 {
		t.Errorf("help must not produce an error line, got %q", buf.String())
	}
}

func TestHelpSubcommandForms(t *testing.T) {
	usageText := renderUsage(terminalWidth())
	for _, args := range [][]string{nil} {
		var err error
		out := captureStdout(t, func() { err = runHelp(args) })
		if err != nil || out != usageText {
			t.Errorf("blk help %v: err = %v, want the usage text", args, err)
		}
	}
	for _, name := range []string{"--help", "-h", "help"} {
		var err error
		out := captureStdout(t, func() { err = dispatch(name, nil) })
		if err != nil || out != usageText {
			t.Errorf("blk %s: err = %v, want the usage text", name, err)
		}
	}
	err := runHelp([]string{"ask", "search"})
	if exitCode(err) != 2 {
		t.Errorf("blk help with two names: exit %d, want 2", exitCode(err))
	}
}

func TestUnknownCommandIsShortAndSuggests(t *testing.T) {
	cases := []struct {
		in, suggest string
	}{
		{"serach", "search"},
		{"sta", "status"},
		{"mdoels", "models"},
		{"logss", "logs"},
		{"comp", "completion"},
		{"xyzzy", ""},
		{"do", ""},
		{"a", ""},
		{"--foo", ""},
	}
	for _, tc := range cases {
		var err error
		stdout, stderr := captureBoth(t, func() {
			err = dispatch(tc.in, nil)
			reportError(os.Stderr, err)
		})
		if exitCode(err) != 2 {
			t.Errorf("blk %s: exit %d, want 2", tc.in, exitCode(err))
		}
		if stdout != "" {
			t.Errorf("blk %s: wrote to stdout: %q", tc.in, stdout)
		}
		if !strings.Contains(stderr, "unknown command") || !strings.Contains(stderr, `Run "blk help" to see all commands.`) {
			t.Errorf("blk %s: stderr lacks the error or the pointer: %q", tc.in, stderr)
		}
		if n := strings.Count(strings.TrimRight(stderr, "\n"), "\n") + 1; n > 3 {
			t.Errorf("blk %s: error is %d lines, want a short message: %q", tc.in, n, stderr)
		}
		if strings.Contains(stderr, "COMMANDS") || strings.Contains(stderr, "USAGE") {
			t.Errorf("blk %s: printed the whole usage", tc.in)
		}
		hasSuggestion := strings.Contains(stderr, "Did you mean")
		if tc.suggest == "" && hasSuggestion {
			t.Errorf("blk %s: unexpected suggestion in %q", tc.in, stderr)
		}
		if tc.suggest != "" && !strings.Contains(stderr, "Did you mean "+tc.suggest+"?") {
			t.Errorf("blk %s: want a suggestion for %s in %q", tc.in, tc.suggest, stderr)
		}
	}
}

func TestHelpForUnknownCommandGetsTheSameTreatment(t *testing.T) {
	err := runHelp([]string{"serach"})
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "Did you mean search?") {
		t.Errorf("blk help serach: err = %v exit %d", err, exitCode(err))
	}
}

func TestMissingArgumentsAreUsageErrors(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
	}{
		{"ask", nil},
		{"ask", []string{"--json"}},
		{"search", nil},
		{"open", nil},
		{"add", nil},
		{"add", []string{"a", "b"}},
		{"hermes", nil},
		{"completion", nil},
	}
	for _, tc := range cases {
		var err error
		captureBoth(t, func() { err = dispatch(tc.cmd, tc.args) })
		if err == nil {
			t.Errorf("blk %s %v: want a usage error", tc.cmd, tc.args)
			continue
		}
		if exitCode(err) != 2 {
			t.Errorf("blk %s %v: exit %d, want 2", tc.cmd, tc.args, exitCode(err))
		}
		msg := err.Error()
		if strings.Contains(msg, "\n") {
			t.Errorf("blk %s: error must be one line: %q", tc.cmd, msg)
		}
		if !strings.Contains(msg, "blk "+tc.cmd+" ") || !strings.Contains(msg, `blk help `+tc.cmd) {
			t.Errorf("blk %s: want an example and a pointer to help: %q", tc.cmd, msg)
		}
		if !strings.HasPrefix(msg, tc.cmd+":") {
			t.Errorf("blk %s: error should start with the command name: %q", tc.cmd, msg)
		}
	}
}

func TestBadFlagIsAUsageErrorWithoutTheRawDump(t *testing.T) {
	var err error
	stdout, stderr := captureBoth(t, func() { err = runSearch([]string{"--bogus", "q"}) })
	if exitCode(err) != 2 {
		t.Errorf("exit %d, want 2", exitCode(err))
	}
	if stdout != "" || stderr != "" {
		t.Errorf("flag package printed on its own: stdout %q stderr %q", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), `blk help search`) {
		t.Errorf("err = %v", err)
	}
}

func TestBadValuesAreUsageErrors(t *testing.T) {
	if _, err := parseAddArgs([]string{"--type", "exe", "x"}); exitCode(err) != 2 {
		t.Errorf("add --type exe: exit %d, want 2", exitCode(err))
	}
	if err := runLogs([]string{"nosuch"}); exitCode(err) != 2 {
		t.Errorf("logs nosuch: exit %d, want 2", exitCode(err))
	}
	if err := runCompletion([]string{"fish"}); exitCode(err) != 2 {
		t.Errorf("completion fish: exit %d, want 2", exitCode(err))
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{flag.ErrHelp, 0},
		{usageErr("x"), 2},
		{errors.New("boom"), 1},
	}
	for _, tc := range cases {
		if got := exitCode(tc.err); got != tc.want {
			t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

func TestSuggestCommand(t *testing.T) {
	cases := map[string]string{
		"serach": "search", "asl": "ask", "hlep": "help", "stat": "status",
		"instal": "install", "hermes": "hermes", "gatway": "gateway",
		"zzzzzz": "", "d": "", "": "",
	}
	for in, want := range cases {
		if got := suggestCommand(in); got != want {
			t.Errorf("suggestCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlainREPLHelpAndBanner(t *testing.T) {
	out := captureStdout(t, replHelp)
	assertMaxWidth(t, "repl help", out, 80)
	assertASCII(t, "repl help", out)
	for _, title := range []string{"ASK AND SEARCH", "SERVICES", "AGENT (HERMES)"} {
		if !strings.Contains(out, title) {
			t.Errorf("repl help lacks the %q group", title)
		}
	}
	for _, name := range []string{"ask", "search", "open", "up", "down", "status", "health", "doctor", "logs", "hermes"} {
		if lineWith(out, wordingDescs[name]) == "" {
			t.Errorf("repl help lacks %q with its verbatim description", name)
		}
	}
	if lineWith(out, "/models") == "" {
		t.Error("repl help lacks /models")
	}
	for _, name := range []string{"/add", "/gateway", "/mcp", "/install", "/completion"} {
		if strings.Contains(out, name+" ") || strings.Contains(out, name+"\n") {
			t.Errorf("repl help lists %s, which the plain REPL does not support", name)
		}
	}
	if !strings.Contains(out, "/quit") || !strings.Contains(out, "Ctrl-D") {
		t.Errorf("repl help must say how to quit:\n%s", out)
	}

	banner := replBanner()
	for _, want := range []string{"/help", "/quit", "Ctrl-D"} {
		if !strings.Contains(banner, want) {
			t.Errorf("banner %q lacks %q", banner, want)
		}
	}
	if n := utf8.RuneCountInString("blkChain  " + banner); n > 80 {
		t.Errorf("banner line is %d columns", n)
	}
}

func TestCompletionOffersEveryCommand(t *testing.T) {
	bash, zsh := bashCompletion(), zshCompletion()
	for _, c := range commandSpecs() {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(c.name) + `\b`)
		if !re.MatchString(bash) || !re.MatchString(zsh) {
			t.Errorf("completion scripts do not offer %q", c.name)
		}
	}
	for name, desc := range wordingDescs {
		if !strings.Contains(zsh, name+":"+zshEscape(desc)) {
			t.Errorf("zsh completion lacks the description line for %q", name)
		}
	}
	for _, s := range []string{bash, zsh} {
		if !strings.Contains(s, "--top-k") || !strings.Contains(s, "--sources") {
			t.Error("completion lost the search or ask flags")
		}
	}
	assertASCII(t, "bash completion", bash)
	assertASCII(t, "zsh completion", zsh)
}

func TestCompletionScriptsParse(t *testing.T) {
	for _, sh := range []struct {
		bin, script string
	}{{"bash", bashCompletion()}, {"zsh", zshCompletion()}} {
		path, err := exec.LookPath(sh.bin)
		if err != nil {
			t.Skipf("%s not installed", sh.bin)
		}
		cmd := exec.Command(path, "-n")
		cmd.Stdin = strings.NewReader(sh.script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s -n rejected the completion script: %v\n%s", sh.bin, err, out)
		}
	}
}

// collapse joins s's words with single spaces, so wrapped help text compares
// with the line it came from.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// A slash command that is also a command-line command reads its description
// from commandSpecs, so the command-line help, /help, the palette, the plain
// REPL /help, and the zsh completion all say the same thing. /models is the one
// slash command with its own text, because it does more than blk models.
func TestSharedCommandWordingHasOneSource(t *testing.T) {
	noColor(t)
	usage := renderUsage(88)
	block := collapse(helpBlock(200))
	repl := collapse(captureStdout(t, replHelp))
	zsh := zshCompletion()
	for _, name := range []string{"ask", "search", "open", "up", "down", "status", "health", "doctor", "models", "logs", "hermes"} {
		spec, ok := lookupCommand(name)
		if !ok {
			t.Fatalf("no spec for %q", name)
		}
		if lineWith(usage, spec.desc) == "" {
			t.Errorf("%s: the usage lacks %q", name, spec.desc)
		}
		if !strings.Contains(collapse(renderCommandHelp(spec, 88)), spec.desc) {
			t.Errorf("%s: blk help %s lacks %q", name, name, spec.desc)
		}
		if !strings.Contains(zsh, name+":"+zshEscape(spec.desc)) {
			t.Errorf("%s: zsh completion lacks %q", name, spec.desc)
		}
		if name == "models" {
			continue
		}
		slash, ok := slashCommand(name)
		if !ok || slash.desc != spec.desc {
			t.Errorf("/%s registry text = %q, want %q", name, slash.desc, spec.desc)
		}
		if items := filterCommands(slashCommands(), name); len(items) == 0 || items[0].desc != spec.desc {
			t.Errorf("/%s palette text differs from %q", name, spec.desc)
		}
		if !strings.Contains(block, spec.desc) {
			t.Errorf("/help lacks /%s's %q", name, spec.desc)
		}
		if !strings.Contains(repl, spec.desc) {
			t.Errorf("the plain REPL /help lacks /%s's %q", name, spec.desc)
		}
	}
	const models = "see all models; turn them on or off, load or unload"
	if c, _ := slashCommand("models"); c.desc != models || !strings.Contains(block, models) || !strings.Contains(repl, models) {
		t.Errorf("/models text = %q, want %q in the registry, /help, and the plain REPL", c.desc, models)
	}
}

// /mode, /agent, and /rag read the same way in the TUI and the plain REPL.
func TestModeCommandsShareOneWording(t *testing.T) {
	noColor(t)
	repl := collapse(captureStdout(t, replHelp))
	for name, want := range map[string]string{
		"mode":  "switch between knowledge-base answers and the Hermes agent (also /agent, /rag)",
		"agent": "use the Hermes agent for questions",
		"rag":   "answer from the knowledge base",
	} {
		if c, _ := slashCommand(name); c.desc != want {
			t.Errorf("/%s registry text = %q, want %q", name, c.desc, want)
		}
		if !strings.Contains(repl, "/"+name+" "+want) {
			t.Errorf("the plain REPL /help lacks /%s %q:\n%s", name, want, repl)
		}
	}
	if block := collapse(helpBlock(200)); !strings.Contains(block, "/mode switch between knowledge-base answers") {
		t.Errorf("/help lacks the /mode row:\n%s", block)
	}
}

// The log command's argument is a service everywhere.
func TestLogsArgumentIsAService(t *testing.T) {
	noColor(t)
	if c, _ := slashCommand("logs"); c.args != "[service]" {
		t.Errorf("/logs args = %q, want [service]", c.args)
	}
	for label, out := range map[string]string{
		"/help":            helpBlock(200),
		"plain REPL /help": captureStdout(t, replHelp),
	} {
		if !strings.Contains(out, "/logs [service]") || strings.Contains(out, "[name]") {
			t.Errorf("%s: want /logs [service]:\n%s", label, out)
		}
	}
	if spec, _ := lookupCommand("logs"); spec.args != "[service]" {
		t.Errorf("blk logs args = %q", spec.args)
	}
}

// blk help env lists the answer sampling variables, each on one row with the
// code default, and no row runs past 80 columns.
func TestEnvHelpListsTheSamplingVariables(t *testing.T) {
	f := func(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
	rows := map[string]string{
		"BLKCHAIN_SYNTH_TEMPERATURE": "", "BLKCHAIN_SYNTH_TOP_P": "",
		"BLKCHAIN_SYNTH_TOP_K": "", "BLKCHAIN_SYNTH_PRESENCE_PENALTY": "",
	}
	for k := range rows {
		t.Setenv(k, "")
	}
	cfg := ragconfig.Load()
	rows["BLKCHAIN_SYNTH_TEMPERATURE"] = f(cfg.SynthTemperature)
	rows["BLKCHAIN_SYNTH_TOP_P"] = f(cfg.SynthTopP)
	rows["BLKCHAIN_SYNTH_TOP_K"] = strconv.Itoa(cfg.SynthTopK)
	rows["BLKCHAIN_SYNTH_PRESENCE_PENALTY"] = f(cfg.SynthPresencePenalty)
	out := renderEnvHelp(80)
	assertMaxWidth(t, "env help", out, 80)
	for name, def := range rows {
		if l := lineWith(out, name); !strings.Contains(l, "(default "+def+")") {
			t.Errorf("ENVIRONMENT row for %s = %q, want it on one row with (default %s)", name, l, def)
		}
	}
}
