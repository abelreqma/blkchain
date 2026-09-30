package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// help.go owns the command line's help surfaces: the command registry (one
// spec per command: its wording, flags, examples, and run function), the
// per-command help renderer, the top-level usage, and the usage-error type
// that gives help and usage mistakes exit code 2. Dispatch in main.go goes
// through the registry, so a command cannot exist without a help entry.

// Command groups, in the order the usage lists them.
const (
	hgAsk      = "ASK AND SEARCH"
	hgServices = "SERVICES"
	hgAgent    = "AGENT (HERMES)"
	hgSetup    = "SETUP"
)

var helpGroups = []string{hgAsk, hgServices, hgAgent, hgSetup}

// cmdSpec describes one command. desc is the shared one-line wording used by
// the usage, per-command help, shell completion, and the plain REPL. A spec
// with no group is a hidden alias-like command: it has help and completion but
// is not listed in the usage.
type cmdSpec struct {
	name     string
	aliases  []string
	args     string
	desc     string
	group    string
	long     string
	flags    func(fs *flag.FlagSet)
	examples []string
	run      func(args []string) error
}

// commandSpecs is the command registry, in usage order. It is a function, not a
// variable, because the run functions read the registry back through
// parseFlags, which would make a package-level initialization cycle.
func commandSpecs() []cmdSpec {
	return []cmdSpec{
		{
			name: "ask", args: "<question...>", group: hgAsk,
			desc: "answer a question, with cited sources",
			long: "Searches the knowledge base, checks that what it found is enough, and writes an answer that cites its sources. " +
				"Use it when you want an answer rather than a list of passages. " +
				"If the passages fall short and a web search key is set, it can also search the web and marks those sources as untrusted. " +
				"It needs the local services and the LLM server running.",
			flags: func(fs *flag.FlagSet) { defineAskFlags(fs, &askOpts{}) },
			examples: []string{
				`blk ask "how do I chain SSRF to RCE?"`,
				`blk ask --sources "what is HTTP request smuggling?"`,
				`blk ask --json "what is IDOR?"`,
			},
			run: runAsk,
		},
		{
			name: "search", args: "<query...>", group: hgAsk,
			desc: "find the most relevant source passages for a query",
			long: "Finds the passages in the knowledge base that best match your query and prints them with their sources and scores. " +
				"It does not use the LLM server, so it is quick. " +
				"Use it to see the raw sources, or to find a file to open with blk open. " +
				"It needs the local services running (blk up).",
			flags: func(fs *flag.FlagSet) { defineSearchFlags(fs, &searchOpts{}, loadConfig().TopK) },
			examples: []string{
				`blk search "SSRF to cloud metadata"`,
				`blk search "JWT none algorithm" --top-k 10`,
				`blk search --type payload "xss polyglot"`,
			},
			run: runSearch,
		},
		{
			name: "sources", group: hgAsk,
			desc: "list indexed sources, with chunk counts",
			long: "Lists each source in the knowledge base with how many chunks it holds, largest first, and the total. " +
				"Use it to confirm what blk add indexed, or to find the names that blk search --source accepts. " +
				"It only reads, and with --json it prints the collection, the total, and a list of source and chunks. " +
				"It needs the local services running (blk up).",
			flags:    func(fs *flag.FlagSet) { defineSourcesFlags(fs, &sourcesOpts{}) },
			examples: []string{"blk sources", "blk sources --json | jq"},
			run:      runSources,
		},
		{
			name: "open", args: "<path>", group: hgAsk,
			desc: "open a cited source in your pager or editor",
			long: "Opens a source that a search or answer cited, in your pager (less unless PAGER is set) or, with --edit, in your editor (EDITOR, then VISUAL, then vi). " +
				"A relative path is looked up from the current folder first, then from the project folder, so a path printed by blk search works as printed. " +
				"With --section and less as the pager, it opens at that heading instead of the top; in the TUI, /open N does this for the cited section. " +
				"A web address is printed, not opened.",
			flags: func(fs *flag.FlagSet) { defineOpenFlags(fs, new(bool), new(string)) },
			examples: []string{
				"blk open sources/notes/ssrf.md",
				`blk open sources/wstg/sqli.md --section "Testing for SQL Injection"`,
				"blk open --edit ./my-notes.md",
			},
			run: runOpen,
		},
		{
			name: "add", args: "<path|url>", group: hgAsk,
			desc: "add your own files, folders, or a web page",
			long: "Adds a file, a folder, or a web page to the knowledge base so that ask and search can use it. " +
				"Adding the same content again only updates what changed. " +
				"Web pages must be public: local and private addresses are refused. " +
				"The local services must be running (blk up).",
			flags: func(fs *flag.FlagSet) { defineAddFlags(fs, new(string), new(string)) },
			examples: []string{
				"blk add ./my-notes.md",
				"blk add ~/notes --source my-notes",
				"blk add https://example.com/writeup",
			},
			run: runAdd,
		},
		{
			name: "up", group: hgServices,
			desc: "start the local services",
			long: "Starts qdrant (in Docker), then embed_server, and reports each one. " +
				"Run it before your first search or ask, and after a restart. " +
				"Services that are already running are left alone. " +
				"It does not start the LLM server, which you run separately.",
			examples: []string{"blk up", "blk status"},
			run:      func(_ []string) error { return runStack("up") },
		},
		{
			name: "down", group: hgServices,
			desc: "stop the local services",
			long: "Stops embed_server and qdrant. " +
				"Use it when you are done, to free memory. " +
				"Your indexed data is kept and comes back the next time you run blk up. " +
				"The LLM server is not touched.",
			examples: []string{"blk down", "blk status"},
			run:      func(_ []string) error { return runStack("down") },
		},
		{
			name: "status", group: hgServices,
			desc: "show whether each local service is running",
			long: "Shows whether qdrant and embed_server are up, with their ports. " +
				"It is a quick look and never starts or stops anything. " +
				"For a fuller check that says what to fix, use blk doctor.",
			examples: []string{"blk status", "blk doctor"},
			run:      func(_ []string) error { return runStack("status") },
		},
		{
			name: "health", group: hgServices,
			desc: "check qdrant, embed_server, and the LLM",
			long: "Checks that qdrant, embed_server, and the LLM server answer, using the same probes as search and ask. " +
				"It prints one line per service, or with --json one object of ok, qdrant, embed_server, and llm, and it changes nothing. " +
				"It exits 0 when all three are up and 1 when any is down, so a script can gate on it. " +
				"blk doctor checks more and says what to fix.",
			flags:    func(fs *flag.FlagSet) { defineHealthFlags(fs, &healthOpts{}) },
			examples: []string{"blk health", "blk health --json", "blk doctor"},
			run:      runHealth,
		},
		{
			name: "doctor", group: hgServices,
			desc: "check the whole setup and say what to fix",
			long: "Checks the whole setup and prints a checklist: the project folder, the Python environment, Docker, qdrant and embed_server, the LLM server, and the Hermes wiring. " +
				"It keeps going after a failed check, so you see everything at once. " +
				"Run it after install, or when something does not work, and follow the hint under each failure.",
			flags:    func(fs *flag.FlagSet) {},
			examples: []string{"blk doctor", "blk up"},
			run:      runDoctor,
		},
		{
			name: "models", group: hgServices,
			desc: "check each model's readiness and speed",
			long: "Checks the chat, embedding, and rerank models and shows whether each is ready and how fast it is, each on its own so one being down does not hide the others. " +
				"It can take up to a minute when a model is slow to load. " +
				"It also shows the switches set with /models in blk: the reranker when it is off, web search, and the chat models hidden from the model picker. " +
				"With --json each entry has an enabled field, the chat entry lists the hidden models, and a web entry reports web search.",
			flags:    func(fs *flag.FlagSet) { defineModelsFlags(fs, new(bool)) },
			examples: []string{"blk models", "blk models --json"},
			run:      runModels,
		},
		{
			name: "logs", args: "[service]", group: hgServices,
			desc: "show the embed_server log; -f follows it",
			long: "Prints the last lines of a service log from the project's .run folder. " +
				"The only service with a log is embed_server, the default. " +
				"Use -f to keep following the log until you press Ctrl-C. " +
				"Logs exist once blk up has started the service.",
			flags: func(fs *flag.FlagSet) { defineLogsFlags(fs, &logsOpts{}) },
			examples: []string{
				"blk logs",
				"blk logs embed_server -n 100",
				"blk logs -f",
			},
			run: runLogs,
		},
		{
			name: "hermes", args: "<prompt...>", group: hgAgent,
			desc: "run one Hermes agent turn with the knowledge base",
			long: "Runs one turn of the Hermes agent with your prompt and prints its reply. " +
				"Hermes has the knowledge-base tools (search and answer) plus its own tools, so it suits multi-step tasks. " +
				"Use blk ask for a plain cited answer. " +
				"Hermes must be installed and on your PATH.",
			examples: []string{
				`blk hermes "summarize the SSRF notes"`,
				`blk hermes "list the XSS payload sources"`,
			},
			run: runHermes,
		},
		{
			name: "gateway", group: hgAgent,
			desc: "set up and start the Hermes gateway for agent mode",
			long: "Prepares Hermes for agent mode and starts its gateway. " +
				"It writes API_SERVER_ENABLED and API_SERVER_KEY into ~/.hermes/.env, using your LLM server key (OMLX_API_KEY or OMLX_API), and keeps a backup when a value changes. " +
				"The key itself is never printed. " +
				"Use --setup-only to write the file and stop without starting the gateway.",
			flags:    func(fs *flag.FlagSet) { defineGatewayFlags(fs, new(bool)) },
			examples: []string{"blk gateway --setup-only", "blk gateway"},
			run:      runGateway,
		},
		{
			name: "mcp", group: hgAgent,
			desc: "serve the knowledge base to Hermes over MCP (stdio)",
			long: "Runs the knowledge base as an MCP server on standard input and output, with two tools: kb_search and kb_answer. " +
				"Hermes or another MCP client starts it for you, so you do not normally run it by hand. " +
				"It needs qdrant and embed_server running, and kb_answer also needs the LLM server.",
			examples: []string{"blk mcp", "blk doctor"},
			run:      runMCP,
		},
		{
			name: "install", group: hgSetup,
			desc: "put blk on your PATH (run once, from the project)",
			long: "Copies this blk binary onto your PATH and remembers the project folder, so blk works from any directory. " +
				"Run it once, from the project folder. " +
				"The default target is ~/.local/bin, and if that folder is not on your PATH it prints the line to add. " +
				"Running it again replaces the old copy.",
			flags:    func(fs *flag.FlagSet) { defineInstallFlags(fs, new(string)) },
			examples: []string{"blk install", "blk install --dir ~/bin"},
			run:      runInstall,
		},
		{
			name: "completion", args: "<bash|zsh>", group: hgSetup,
			desc: "print a bash or zsh completion script",
			long: "Prints a completion script for bash or zsh. " +
				"Load it from your shell startup file to complete command names, flags, and service names with Tab. " +
				"In zsh the commands are listed with their descriptions.",
			examples: []string{
				"source <(blk completion zsh)",
				"echo 'source <(blk completion bash)' >> ~/.bashrc",
			},
			run: runCompletion,
		},
		{
			name: "version", aliases: []string{"--version", "-v"}, group: hgSetup,
			desc: "show version and build info",
			long: "Prints the blk version, the git commit it was built from, and the Go version that built it. " +
				"Include it when you report a problem.",
			examples: []string{"blk version", "blk --version"},
			run:      func(_ []string) error { printVersion(os.Stdout); return nil },
		},
		{
			name: "help", aliases: []string{"-h", "--help"}, args: "[command]", group: hgSetup,
			desc: "show help for blk or for one command",
			long: "Shows the list of commands. " +
				"Give a command name to see that command's flags and examples. " +
				"Running blk <command> --help does the same. " +
				"blk help env lists every environment variable blk reads.",
			examples: []string{"blk help", "blk help search", "blk search --help"},
			run:      runHelp,
		},
		{
			name: "repl", aliases: []string{"chat"},
			desc: "start the interactive session (same as running blk alone)",
			long: "Starts the interactive session, the same as running blk with no command. " +
				"In a plain terminal or a pipe it falls back to a simple line-by-line mode. " +
				"Type /help inside it to list its commands.",
			examples: []string{"blk repl", "echo /status | blk repl"},
			run:      func(_ []string) error { return runREPL() },
		},
	}
}

// lookupCommand finds a spec by its name or one of its aliases.
func lookupCommand(name string) (cmdSpec, bool) {
	for _, c := range commandSpecs() {
		if c.name == name {
			return c, true
		}
		for _, a := range c.aliases {
			if a == name {
				return c, true
			}
		}
	}
	return cmdSpec{}, false
}

// --- usage errors and exit codes ---

// usageError is a mistake in how blk was invoked (unknown command, missing
// argument, bad flag). It exits with code 2. hint, when set, is printed on its
// own line after the error.
type usageError struct{ msg, hint string }

func (e *usageError) Error() string { return e.msg }

func usageErr(format string, a ...any) error {
	return &usageError{msg: fmt.Sprintf(format, a...)}
}

// missingArg builds the one-line error for a missing or wrong argument: what is
// wrong, a concrete example, and where to read more.
func missingArg(cmd, what, example string) error {
	return usageErr(`%s: %s. Example: blk %s. See "blk help %s".`, cmd, what, example, cmd)
}

// errDegraded is returned by blk health when a service is down. The command has
// already printed its report, so reportError stays silent and exitCode maps it
// to 1.
var errDegraded = errors.New("one or more services are down")

// exitCode is the process exit status for the error a command returned: 0 for
// success and for a help request, 2 for a usage error, 1 for anything else
// (including errDegraded).
func exitCode(err error) int {
	var ue *usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		return 2
	default:
		return 1
	}
}

// reportError prints err the way every command failure is shown: the error
// mark and the message, then the hint of a usage error. A nil error, a help
// request, and errDegraded (already reported by the command) print nothing.
func reportError(w io.Writer, err error) {
	if err == nil || errors.Is(err, flag.ErrHelp) || errors.Is(err, errDegraded) {
		return
	}
	fmt.Fprintf(w, "%s %s\n", errMark(), sanitizeTerminal(err.Error()))
	var ue *usageError
	if errors.As(err, &ue) && ue.hint != "" {
		fmt.Fprintln(w, errStyle(Meta, ue.hint))
	}
}

// unknownCommand is the short error for a command name blk does not have, with
// a suggestion when one is close.
func unknownCommand(name string) error {
	msg := fmt.Sprintf("unknown command %q", name)
	if s := suggestCommand(name); s != "" {
		msg += fmt.Sprintf(". Did you mean %s?", s)
	}
	return &usageError{msg: msg, hint: `Run "blk help" to see all commands.`}
}

// suggestCommand returns the command a mistyped name most likely meant: the one
// command it is a prefix of, else the closest name within edit distance 2 (and
// less than the name's own length, so one or two letters never guess). It
// returns "" when nothing is close.
func suggestCommand(name string) string {
	name = strings.ToLower(name)
	if name == "" {
		return ""
	}
	specs := commandSpecs()
	var prefixed []string
	for _, c := range specs {
		if strings.HasPrefix(c.name, name) && c.name != name {
			prefixed = append(prefixed, c.name)
		}
	}
	if len(prefixed) == 1 {
		return prefixed[0]
	}
	best, bestD := "", 3
	for _, c := range specs {
		if d := editDistance(name, c.name); d < bestD && d < len(name) {
			best, bestD = c.name, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// --- flag sets ---

// newFlagSet returns the flag set every command uses. The flag package never
// prints on its own: its raw "Usage of" dump and error line are replaced by
// parseFlags, which prints the help text for a help request and returns a
// usage error for a bad flag.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// commandFlagSet builds the flag set a spec documents, for help and completion.
func commandFlagSet(c cmdSpec) *flag.FlagSet {
	fs := newFlagSet(c.name)
	if c.flags != nil {
		c.flags(fs)
	}
	return fs
}

// parseFlags parses args. A help flag prints the command's help to stdout and
// returns flag.ErrHelp (exit 0, no error line). Any other flag error becomes a
// usage error that points to the command's help.
func parseFlags(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, flag.ErrHelp):
		if c, ok := lookupCommand(fs.Name()); ok {
			printCommandHelp(os.Stdout, c)
		}
		return flag.ErrHelp
	default:
		msg := err.Error()
		if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
			dash := "--"
			if len(name) == 1 {
				dash = "-"
			}
			msg = "unknown flag " + dash + name
		}
		return usageErr(`%s: %s. See "blk help %s".`, fs.Name(), msg, fs.Name())
	}
}

// helpRequested reports whether the first argument asks for help.
func helpRequested(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "-h", "--help", "-help":
		return true
	}
	return false
}

// flagRows lists a flag set's flags for the FLAGS section, sorted by name. The
// argument placeholder is the backquoted word in a flag's usage text. A default
// is added when it is meaningful (not empty, 0, or false) and the text does
// not already state one.
func flagRows(fs *flag.FlagSet) []helpRow {
	var rows []helpRow
	fs.VisitAll(func(f *flag.Flag) {
		placeholder, usage := flag.UnquoteUsage(f)
		left := "--" + f.Name
		if len(f.Name) == 1 {
			left = "-" + f.Name
		}
		if placeholder != "" {
			left += " " + placeholder
		}
		switch f.DefValue {
		case "", "0", "false":
		default:
			if !strings.Contains(usage, "default") {
				usage += " (default " + f.DefValue + ")"
			}
		}
		rows = append(rows, helpRow{left, usage})
	})
	return rows
}

// flagNames lists a flag set's flags as typed, for shell completion.
func flagNames(fs *flag.FlagSet) []string {
	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		if len(f.Name) == 1 {
			names = append(names, "-"+f.Name)
		} else {
			names = append(names, "--"+f.Name)
		}
	})
	return names
}

// --- rendering ---

// helpRow is one name and description pair in a help section.
type helpRow struct{ name, desc string }

// helpWidth is the width help is laid out to: the terminal width, never wider
// than 88 columns and never narrower than 30.
func helpWidth(width int) int {
	if width > 88 {
		width = 88
	}
	if width < 30 {
		width = 30
	}
	return width
}

func helpHeading(b *strings.Builder, title string) {
	b.WriteString(" " + Section.Render(title) + "\n")
}

// writeRows renders rows as two aligned columns at indent, the name column as
// wide as the widest name.
func writeRows(b *strings.Builder, rows []helpRow, indent, total int, nameStyle, descStyle lipgloss.Style) {
	writeCols(b, rows, indent, rowsNameWidth(rows), total, renderWith(nameStyle), descStyle)
}

func rowsNameWidth(rows []helpRow) int {
	w := 0
	for _, r := range rows {
		w = max(w, len(r.name))
	}
	return w
}

// writeCols renders rows as two columns at indent with a name column nameW
// wide, so rows from several sections can share one column. name styles each
// name, which lets a name mix styles (a command and its arguments). A
// description that does not fit wraps under itself. When the terminal is too
// narrow for two columns, each description goes on its own line under its
// name.
func writeCols(b *strings.Builder, rows []helpRow, indent, nameW, total int, name func(string) string, descStyle lipgloss.Style) {
	const gap = 2
	lead := strings.Repeat(" ", indent)
	descW := total - indent - nameW - gap
	for _, r := range rows {
		if descW < 20 {
			b.WriteString(lead + name(r.name) + "\n")
			writePara(b, r.desc, indent+2, total, descStyle)
			continue
		}
		for i, ln := range strings.Split(wrapIndent(r.desc, 0, descW), "\n") {
			if i == 0 {
				b.WriteString(lead + name(r.name) + strings.Repeat(" ", max(0, nameW-len(r.name))+gap) + descStyle.Render(ln) + "\n")
			} else {
				b.WriteString(strings.Repeat(" ", indent+nameW+gap) + descStyle.Render(ln) + "\n")
			}
		}
	}
}

// renderWith styles a whole row name with st.
func renderWith(st lipgloss.Style) func(string) string {
	return func(s string) string { return st.Render(s) }
}

// twoPart styles a row name's first word with first and the rest with rest: a
// command and its argument signature, or a flag and its placeholder.
func twoPart(first, rest lipgloss.Style) func(string) string {
	return func(s string) string {
		head, tail, ok := strings.Cut(s, " ")
		if !ok {
			return first.Render(s)
		}
		return first.Render(head) + " " + rest.Render(tail)
	}
}

// exKind is the role of one word of an example command line.
type exKind int

const (
	exOther exKind = iota // an argument, a path, or a shell word
	exBlk                 // the word blk
	exSub                 // the command right after blk
	exStr                 // a quoted string
	exFlag                // -x or --name
	exValue               // the word after a flag that takes a value
	exPlace               // a placeholder: <name> or [name]
)

// style is the help style for a word of this kind.
func (k exKind) style() lipgloss.Style {
	switch k {
	case exBlk, exSub:
		return Cmd
	case exStr:
		return Str
	case exFlag:
		return Flag
	case exPlace:
		return Arg
	}
	return Body
}

// exTok is one word of an example and its role.
type exTok struct {
	text string
	kind exKind
}

// tokenizeExample splits an example into words in one pass: a quoted span is
// one word even with spaces in it (an unterminated quote runs to the end), and
// each word is classified as it is read. The word after a flag is its value
// only when the command's own flag set says the flag takes one.
func tokenizeExample(ex string) []exTok {
	var toks []exTok
	var fs *flag.FlagSet
	afterBlk, wantValue := false, false
	for i := 0; i < len(ex); {
		if ex[i] == ' ' {
			i++
			continue
		}
		start := i
		var quote byte
		for ; i < len(ex); i++ {
			switch ch := ex[i]; {
			case quote != 0:
				if ch == quote {
					quote = 0
				}
			case ch == '"' || ch == '\'':
				quote = ch
			}
			if quote == 0 && ex[i] == ' ' {
				break
			}
		}
		w := ex[start:i]
		kind := exOther
		switch {
		case w[0] == '"' || w[0] == '\'':
			kind = exStr
		case wantValue:
			kind = exValue
		case len(w) > 1 && w[0] == '-':
			kind = exFlag
		case w == "blk":
			kind = exBlk
		case len(w) > 1 && (w[0] == '<' && w[len(w)-1] == '>' || w[0] == '[' && w[len(w)-1] == ']'):
			kind = exPlace
		case afterBlk:
			kind, fs = exSub, nil
			if c, ok := lookupCommand(w); ok {
				fs = commandFlagSet(c)
			}
		}
		afterBlk = kind == exBlk
		wantValue = kind == exFlag && flagTakesValue(fs, w)
		toks = append(toks, exTok{w, kind})
	}
	return toks
}

// flagTakesValue reports whether the flag word w (without =value) is in fs and
// is not a bool flag.
func flagTakesValue(fs *flag.FlagSet, w string) bool {
	if fs == nil || strings.Contains(w, "=") {
		return false
	}
	f := fs.Lookup(strings.TrimLeft(w, "-"))
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !b.IsBoolFlag()
}

// styleWords highlights a single-spaced command line such as a synopsis.
func styleWords(s string) string {
	toks := tokenizeExample(s)
	parts := make([]string, len(toks))
	for i, tk := range toks {
		parts[i] = tk.kind.style().Render(tk.text)
	}
	return strings.Join(parts, " ")
}

// exampleLines lays out one example at indent behind a muted $ prompt,
// highlighted word by word. A word that does not fit starts a continuation
// line under the command, and a word longer than a whole line is split. The
// examples are fixed ASCII strings, so byte lengths are column counts.
func exampleLines(ex string, indent, total int) []string {
	cont := strings.Repeat(" ", indent+2)
	var lines []string
	line, col, fresh := strings.Repeat(" ", indent)+Arg.Render("$"), indent+1, false
	for _, tk := range tokenizeExample(ex) {
		text, st := tk.text, tk.kind.style()
		if !fresh && col+1+len(text) > total {
			lines, line, col, fresh = append(lines, line), cont, indent+2, true
		}
		for {
			sep := " "
			if fresh {
				sep = ""
			}
			room := total - col - len(sep)
			if len(text) <= room || room < 1 {
				line += sep + st.Render(text)
				col += len(sep) + len(text)
				fresh = false
				break
			}
			line += sep + st.Render(text[:room])
			text = text[room:]
			lines, line, col, fresh = append(lines, line), cont, indent+2, true
		}
	}
	return append(lines, line)
}

// writeNote renders a muted note at indent 1, wrapped to total, with each
// command text in code highlighted as the examples are. A command text that
// wrapping splits stays muted.
func writeNote(b *strings.Builder, text string, total int, code ...string) {
	for _, ln := range strings.Split(wrapIndent(text, 1, total), "\n") {
		ln = strings.TrimSpace(ln)
		var out strings.Builder
		for ln != "" {
			at, hit := -1, ""
			for _, c := range code {
				if i := strings.Index(ln, c); i >= 0 && (at < 0 || i < at) {
					at, hit = i, c
				}
			}
			if at < 0 {
				out.WriteString(Meta.Render(ln))
				break
			}
			if at > 0 {
				out.WriteString(Meta.Render(ln[:at]))
			}
			out.WriteString(styleWords(hit))
			ln = ln[at+len(hit):]
		}
		b.WriteString(" " + out.String() + "\n")
	}
}

func writeExamples(b *strings.Builder, examples []string, total int) {
	for _, ex := range examples {
		for _, ln := range exampleLines(ex, 3, total) {
			b.WriteString(ln + "\n")
		}
	}
}

// writePara renders wrapped prose at indent.
func writePara(b *strings.Builder, text string, indent, total int, style lipgloss.Style) {
	lead := strings.Repeat(" ", indent)
	for _, ln := range strings.Split(wrapIndent(text, indent, total), "\n") {
		b.WriteString(lead + style.Render(strings.TrimSpace(ln)) + "\n")
	}
}

// renderCommandHelp lays out one command's help at width: a title line and the
// one-line description, then DESCRIPTION, FLAGS, and EXAMPLES (each left out
// when empty) and a closing pointer to blk help.
func renderCommandHelp(c cmdSpec, width int) string {
	total := helpWidth(width)
	var b strings.Builder

	b.WriteString(" " + styleWords(strings.TrimSpace("blk "+c.name+" "+c.args)) + "\n")
	writePara(&b, c.desc, 1, total, Body)

	if c.long != "" {
		b.WriteString("\n")
		helpHeading(&b, "DESCRIPTION")
		writePara(&b, c.long, 3, total, Body)
	}
	if c.flags != nil {
		if rows := flagRows(commandFlagSet(c)); len(rows) > 0 {
			b.WriteString("\n")
			helpHeading(&b, "FLAGS")
			writeCols(&b, rows, 3, rowsNameWidth(rows), total, twoPart(Flag, Arg), Body)
		}
	}
	if len(c.examples) > 0 {
		b.WriteString("\n")
		helpHeading(&b, "EXAMPLES")
		writeExamples(&b, c.examples, total)
	}
	b.WriteString("\n")
	writePara(&b, `Run "blk help" to see all commands.`, 1, total, Meta)
	return b.String()
}

func printCommandHelp(w io.Writer, c cmdSpec) {
	fmt.Fprint(w, renderCommandHelp(c, terminalWidth()))
}

// usageTagline follows the README's own description of blkChain: local RAG
// over offensive-security knowledge. It stays under 45 characters.
const usageTagline = "local RAG over offensive-security knowledge"

// usageExamples are the top-level EXAMPLES: starting and checking the
// services, ask, and search with a flag after the query.
var usageExamples = []string{
	"blk up && blk doctor",
	`blk ask "how do I chain SSRF to RCE?"`,
	`blk search "SSRF to cloud metadata" --top-k 10`,
}

// usageEnvShort names the variables the top-level ENVIRONMENT shows; blk help
// env lists them all.
var usageEnvShort = []string{"OMLX_BASE_URL", "OMLX_MODEL", "TAVILY_SETUP_TOKEN", "BLK_THEME"}

// rowGroup is a titled block of rows: an ENVIRONMENT group or a REPL help group.
type rowGroup struct {
	title string
	rows  []helpRow
}

// usageEnv is the ENVIRONMENT section. Each name, meaning, and default was
// checked against the code that reads it. Secret values are never printed.
func usageEnv() []rowGroup {
	return []rowGroup{
		{"LLM", []helpRow{
			{"OMLX_BASE_URL", "LLM server URL (default " + defaultOMLXBaseURL + ")"},
			{"OMLX_MODEL", "model to use (default: first one the server lists)"},
			{"OMLX_API_KEY", "key for the LLM server, if it needs one"},
			{"BLKCHAIN_TIMEOUT_SECONDS", "seconds before a request gives up (default 300)"},
		}},
		{"LLM ANSWER SAMPLING", []helpRow{
			{"BLKCHAIN_SYNTH_TEMPERATURE", "temperature, 0 to 2 (default 0.7)"},
			{"BLKCHAIN_SYNTH_TOP_P", "top_p, over 0 up to 1 (default 0.95)"},
			{"BLKCHAIN_SYNTH_TOP_K", "top_k, 0 to 1000 (default 64)"},
			{"BLKCHAIN_SYNTH_PRESENCE_PENALTY", "presence penalty, -2 to 2 (default 0.5)"},
		}},
		{"RETRIEVAL", []helpRow{
			{"BLKCHAIN_ROOT", "project folder (default: found automatically)"},
			{"BLKCHAIN_COLLECTION", "name of the index to search (default " + defaultCollection + ")"},
			{"QDRANT_GRPC_URL", "qdrant gRPC address (default 127.0.0.1:6334)"},
		}},
		{"WEB SEARCH", []helpRow{
			{"TAVILY_SETUP_TOKEN", "Tavily key; lets ask search the web (default: off)"},
		}},
		{"DISPLAY", []helpRow{
			{"NO_COLOR", "any value turns colors off"},
			{"BLK_THEME", "light, dark, or auto (default auto)"},
			{"BLK_ACCENT", "slate gives a blue accent (default: off)"},
			{"BLK_REDUCE_MOTION", "1 replaces the spinner with a static line"},
		}},
	}
}

// usageEnvRows returns the rows named in usageEnvShort, taken from usageEnv so
// the wording has one source, and how many variables usageEnv lists in all.
func usageEnvRows() ([]helpRow, int) {
	byName := map[string]helpRow{}
	for _, g := range usageEnv() {
		for _, r := range g.rows {
			byName[r.name] = r
		}
	}
	rows := make([]helpRow, len(usageEnvShort))
	for i, name := range usageEnvShort {
		rows[i] = byName[name]
	}
	return rows, len(byName)
}

// renderUsage lays out the top-level help (blk help, blk --help) at width: a
// title and rule, then one level of sections that share one name column.
func renderUsage(width int) string {
	total := helpWidth(width)
	var b strings.Builder

	v, _, _, _ := versionInfo()
	b.WriteString(" " + headerLine(Title.Render("blk")+"  "+Body.Render(usageTagline), Meta.Render(v), total) + "\n")
	b.WriteString(" " + RuleS.Render(strings.Repeat(barRune(), wrapWidth(total, 78))) + "\n\n")

	synopsis := []helpRow{
		{"blk", "start the interactive session"},
		{"blk <command> [flags]", "run one command; flags go before or after the query"},
	}
	groups := map[string][]helpRow{}
	for _, c := range commandSpecs() {
		if c.group != "" {
			groups[c.group] = append(groups[c.group], helpRow{strings.TrimSpace(c.name + " " + c.args), c.desc})
		}
	}
	envRows, envCount := usageEnvRows()
	nameW := max(rowsNameWidth(synopsis), rowsNameWidth(envRows))
	for _, rows := range groups {
		nameW = max(nameW, rowsNameWidth(rows))
	}

	helpHeading(&b, "USAGE")
	writeCols(&b, synopsis, 3, nameW, total, styleWords, Body)
	for _, group := range helpGroups {
		b.WriteString("\n")
		helpHeading(&b, group)
		writeCols(&b, groups[group], 3, nameW, total, twoPart(Cmd, Arg), Body)
	}

	b.WriteString("\n")
	helpHeading(&b, "EXAMPLES")
	writeExamples(&b, usageExamples, total)

	b.WriteString("\n")
	helpHeading(&b, "ENVIRONMENT")
	writeCols(&b, envRows, 3, nameW, total, renderWith(Cmd), Body)

	b.WriteString("\n")
	writeNote(&b, "Add --json to ask, search, or models for machine-readable output.", total, "--json")
	writeNote(&b, fmt.Sprintf(`Run "blk help <command>" for its flags, or "blk help env" for all %d variables.`, envCount), total,
		"blk help <command>", "blk help env")
	return b.String()
}

// renderEnvHelp lays out the blk help env topic at width: every variable, in
// the usageEnv groups, with the per-command help's title and closing line.
func renderEnvHelp(width int) string {
	total := helpWidth(width)
	var b strings.Builder
	b.WriteString(" " + styleWords("blk help env") + "\n")
	writePara(&b, "the environment variables blk reads", 1, total, Body)
	// Each group aligns to its own widest name, so the long sampling names do
	// not push every other row onto two lines.
	for _, g := range usageEnv() {
		b.WriteString("\n")
		helpHeading(&b, g.title)
		writeRows(&b, g.rows, 3, total, Cmd, Body)
	}
	b.WriteString("\n")
	writePara(&b, `Run "blk help" to see all commands.`, 1, total, Meta)
	return b.String()
}

// usage prints the top-level help to w.
func usage(w *os.File) {
	fmt.Fprint(w, renderUsage(terminalWidth()))
}

// runHelp implements `blk help [command]`.
func runHelp(args []string) error {
	switch len(args) {
	case 0:
		usage(os.Stdout)
		return nil
	case 1:
		if args[0] == "env" || args[0] == "environment" {
			fmt.Fprint(os.Stdout, renderEnvHelp(terminalWidth()))
			return nil
		}
		c, ok := lookupCommand(args[0])
		if !ok {
			return unknownCommand(args[0])
		}
		printCommandHelp(os.Stdout, c)
		return nil
	default:
		return missingArg("help", "expected one command name", "help search")
	}
}
