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
			desc: "answer a question from the knowledge base, with cited sources",
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
			flags: func(fs *flag.FlagSet) { defineSearchFlags(fs, &searchOpts{}) },
			examples: []string{
				`blk search "SSRF to cloud metadata"`,
				`blk search "JWT none algorithm" --top-k 10`,
				`blk search --type payload "xss polyglot"`,
			},
			run: runSearch,
		},
		{
			name: "open", args: "<path>", group: hgAsk,
			desc: "open a cited source in your pager or editor",
			long: "Opens a source that a search or answer cited, in your pager (less unless PAGER is set) or, with --edit, in your editor (EDITOR, then VISUAL, then vi). " +
				"A relative path is looked up from the current folder first, then from the project folder, so a path printed by blk search works as printed. " +
				"A web address is printed, not opened.",
			flags: func(fs *flag.FlagSet) { defineOpenFlags(fs, new(bool)) },
			examples: []string{
				"blk open sources/notes/ssrf.md",
				"blk open --edit ./my-notes.md",
			},
			run: runOpen,
		},
		{
			name: "add", args: "<path|url>", group: hgAsk,
			desc: "add your own files, folders, or a web page to the knowledge base",
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
			long: "Starts qdrant (in Docker), then embed_server and the API, and reports each one. " +
				"Run it before your first search or ask, and after a restart. " +
				"Services that are already running are left alone. " +
				"It does not start the LLM server, which you run separately.",
			examples: []string{"blk up", "blk status"},
			run:      func(_ []string) error { return runStack("up") },
		},
		{
			name: "down", group: hgServices,
			desc: "stop the local services",
			long: "Stops the API, embed_server, and qdrant. " +
				"Use it when you are done, to free memory. " +
				"Your indexed data is kept and comes back the next time you run blk up. " +
				"The LLM server is not touched.",
			examples: []string{"blk down", "blk status"},
			run:      func(_ []string) error { return runStack("down") },
		},
		{
			name: "status", group: hgServices,
			desc: "show whether each local service is running",
			long: "Shows whether qdrant, embed_server, and the API are up, with their ports. " +
				"It is a quick look and never starts or stops anything. " +
				"For a fuller check that says what to fix, use blk doctor.",
			examples: []string{"blk status", "blk doctor"},
			run:      func(_ []string) error { return runStack("status") },
		},
		{
			name: "health", group: hgServices,
			desc: "check qdrant, embed_server, and the LLM",
			long: "Checks that qdrant, embed_server, and the LLM server answer, using the same probes as search and ask. " +
				"Use it when a search or answer fails or hangs. " +
				"It prints one line per service and changes nothing. " +
				"blk doctor checks more and says what to fix.",
			flags:    func(fs *flag.FlagSet) {},
			examples: []string{"blk health", "blk doctor"},
			run:      runHealth,
		},
		{
			name: "doctor", group: hgServices,
			desc: "check the whole setup and say what to fix",
			long: "Checks the whole setup and prints a checklist: the project folder, the Python environment, Docker, the three services, the LLM server, and the Hermes wiring. " +
				"It keeps going after a failed check, so you see everything at once. " +
				"Run it after install, or when something does not work, and follow the hint under each failure.",
			flags:    func(fs *flag.FlagSet) {},
			examples: []string{"blk doctor", "blk up"},
			run:      runDoctor,
		},
		{
			name: "models", group: hgServices,
			desc: "check the chat, embedding, and rerank models and their speed",
			long: "Checks the chat, embedding, and rerank models and times each one. " +
				"For each it shows whether it is ready and how fast it is. " +
				"Each model is checked on its own, so one being down does not hide the others. " +
				"It can take up to a minute when a model is slow to load.",
			flags:    func(fs *flag.FlagSet) { defineModelsFlags(fs, new(bool)) },
			examples: []string{"blk models", "blk models --json"},
			run:      runModels,
		},
		{
			name: "logs", args: "[service]", group: hgServices,
			desc: "show a service log (api or embed_server); -f follows it",
			long: "Prints the last lines of a service log from the project's .run folder. " +
				"The service is api or embed_server, and api is the default. " +
				"Use -f to keep following the log until you press Ctrl-C. " +
				"Logs exist once blk up has started the service.",
			flags: func(fs *flag.FlagSet) { defineLogsFlags(fs, &logsOpts{}) },
			examples: []string{
				"blk logs",
				"blk logs embed_server -n 100",
				"blk logs api -f",
			},
			run: runLogs,
		},
		{
			name: "hermes", args: "<prompt...>", group: hgAgent,
			desc: "run one Hermes agent turn with the knowledge-base tools",
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
				"Running blk <command> --help does the same.",
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

// exitCode is the process exit status for the error a command returned: 0 for
// success and for a help request, 2 for a usage error, 1 for anything else.
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
// mark and the message, then the hint of a usage error. A nil error and a
// help request print nothing.
func reportError(w io.Writer, err error) {
	if err == nil || errors.Is(err, flag.ErrHelp) {
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
	b.WriteString(" " + H2.Render(title) + "\n")
}

// writeRows renders rows as two aligned columns at indent. A description that
// does not fit wraps under itself. When the terminal is too narrow for two
// columns, each description goes on its own line under its name.
func writeRows(b *strings.Builder, rows []helpRow, indent, total int, nameStyle, descStyle lipgloss.Style) {
	nameW := 0
	for _, r := range rows {
		if len(r.name) > nameW {
			nameW = len(r.name)
		}
	}
	const gap = 2
	lead := strings.Repeat(" ", indent)
	descW := total - indent - nameW - gap
	for _, r := range rows {
		if descW < 20 {
			b.WriteString(lead + nameStyle.Render(r.name) + "\n")
			writePara(b, r.desc, indent+2, total, descStyle)
			continue
		}
		for i, ln := range strings.Split(wrapIndent(r.desc, 0, descW), "\n") {
			if i == 0 {
				b.WriteString(lead + nameStyle.Render(pad(r.name, nameW)) + strings.Repeat(" ", gap) + descStyle.Render(ln) + "\n")
			} else {
				b.WriteString(strings.Repeat(" ", indent+nameW+gap) + descStyle.Render(ln) + "\n")
			}
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

	title := strings.TrimSpace("blk " + c.name + " " + c.args)
	writePara(&b, title, 1, total, H1)
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
			writeRows(&b, rows, 3, total, Key, Meta)
		}
	}
	if len(c.examples) > 0 {
		b.WriteString("\n")
		helpHeading(&b, "EXAMPLES")
		for _, ex := range c.examples {
			writePara(&b, ex, 3, total, Key)
		}
	}
	b.WriteString("\n")
	writePara(&b, `Run "blk help" to see all commands.`, 1, total, Meta)
	return b.String()
}

func printCommandHelp(w io.Writer, c cmdSpec) {
	fmt.Fprint(w, renderCommandHelp(c, terminalWidth()))
}

// usageExamples are the top-level EXAMPLES: ask, search with a flag, add, and
// starting and checking the services.
var usageExamples = []string{
	`blk ask "how do I chain SSRF to RCE?"`,
	`blk search "SSRF to cloud metadata" --top-k 10`,
	"blk add ./my-notes.md",
	"blk up",
	"blk status",
	"blk doctor",
}

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

// renderUsage lays out the top-level help (blk help, blk --help) at width.
func renderUsage(width int) string {
	total := helpWidth(width)
	var b strings.Builder

	v, _, _, _ := versionInfo()
	b.WriteString(" " + headerLine(H1.Render("blk "+Glyph(GlyphSep)+" knowledge-base client"), Meta.Render(v), total) + "\n")
	b.WriteString(" " + RuleS.Render(strings.Repeat(barRune(), wrapWidth(total, 78))) + "\n\n")

	helpHeading(&b, "USAGE")
	writeRows(&b, []helpRow{
		{"blk", "start the interactive session"},
		{"blk <command> [flags]", "run one command"},
	}, 3, total, Key, Body)

	b.WriteString("\n")
	helpHeading(&b, "COMMANDS")
	nameW := 0
	specs := commandSpecs()
	for _, c := range specs {
		if c.group != "" && len(c.name) > nameW {
			nameW = len(c.name)
		}
	}
	for gi, group := range helpGroups {
		if gi > 0 {
			b.WriteString("\n")
		}
		b.WriteString("  " + Meta.Render(group) + "\n")
		var rows []helpRow
		for _, c := range specs {
			if c.group == group {
				rows = append(rows, helpRow{pad(c.name, nameW), c.desc})
			}
		}
		writeRows(&b, rows, 3, total, Key, Body)
	}
	b.WriteString("\n")
	writePara(&b, "Add --json to ask, search, or models for machine-readable output.", 3, total, Meta)
	writePara(&b, "Flags can go before or after the query.", 3, total, Meta)

	b.WriteString("\n")
	helpHeading(&b, "EXAMPLES")
	for _, ex := range usageExamples {
		writePara(&b, ex, 3, total, Key)
	}

	b.WriteString("\n")
	helpHeading(&b, "ENVIRONMENT")
	env := usageEnv()
	envW := 0
	for _, g := range env {
		for _, r := range g.rows {
			if len(r.name) > envW {
				envW = len(r.name)
			}
		}
	}
	for gi, g := range env {
		if gi > 0 {
			b.WriteString("\n")
		}
		b.WriteString("  " + Meta.Render(g.title) + "\n")
		rows := make([]helpRow, len(g.rows))
		for i, r := range g.rows {
			rows[i] = helpRow{pad(r.name, envW), r.desc}
		}
		writeRows(&b, rows, 3, total, Key, Meta)
	}

	b.WriteString("\n")
	writePara(&b, `Run "blk help <command>" for flags and examples.`, 1, total, Meta)
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
