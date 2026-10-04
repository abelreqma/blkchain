package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/structgen"
)

// defaultAnalyzeMaxInputBytes bounds the subject text blk analyze reads from an
// argument, a file, or stdin.
const defaultAnalyzeMaxInputBytes = 1 << 20

// analyzeMaxInputBytes is the subject size cap: BLKCHAIN_ANALYZE_MAX_INPUT_BYTES
// when set to a positive integer, else the default.
func analyzeMaxInputBytes() int {
	if v := strings.TrimSpace(os.Getenv("BLKCHAIN_ANALYZE_MAX_INPUT_BYTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultAnalyzeMaxInputBytes
}

// analyzeOpts holds the flags of blk analyze.
type analyzeOpts struct {
	schema   string
	input    string
	retrieve bool
	topK     int
	model    string
}

func defineAnalyzeFlags(fs *flag.FlagSet, o *analyzeOpts, defaultTopK int) {
	fs.StringVar(&o.schema, "schema", "", "the output schema `NAME` (required)")
	fs.StringVar(&o.input, "input", "", "read the subject from `FILE` instead of the argument")
	fs.BoolVar(&o.retrieve, "retrieve", false, "add matching knowledge-base context before analyzing")
	fs.IntVar(&o.topK, "top-k", 0, fmt.Sprintf("with --retrieve, use `N` chunks (default %d)", defaultTopK))
	fs.StringVar(&o.model, "model", "", "override the chat model `ID`")
}

// analyzeGen builds the LLM client structgen uses. It is a variable so tests can
// inject a fake generator.
var analyzeGen = func(cfg ragconfig.Config, model string) (structgen.Generator, error) {
	return newOMLX(cfg, model)
}

// analyzeGrounding retrieves and formats knowledge-base context for --retrieve.
// It is a variable so tests can stub retrieval. It returns the context block and
// the number of chunks used.
var analyzeGrounding = func(ctx context.Context, cfg ragconfig.Config, subject string, topK int) (string, int, error) {
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		return "", 0, err
	}
	defer rc.Close()
	results, err := rc.Search(ctx, subject, topK, nil)
	if err != nil {
		return "", 0, err
	}
	chunks := boundChunks(cfg, results)
	return buildContext(chunks), len(chunks), nil
}

func runAnalyze(args []string) error {
	var o analyzeOpts
	cfg := loadConfig()
	fs := newFlagSet("analyze")
	defineAnalyzeFlags(fs, &o, cfg.TopK)
	valueFlags := map[string]bool{"schema": true, "input": true, "top-k": true, "model": true}
	if err := parseFlags(fs, reorder(args, valueFlags)); err != nil {
		return err
	}

	schema, ok := structgen.Lookup(o.schema)
	if !ok {
		return missingArg("analyze",
			fmt.Sprintf("unknown or missing --schema %q; valid: %s", o.schema, strings.Join(structgen.SchemaNames(), ", ")),
			`analyze --schema finding "reflected XSS in the q parameter"`)
	}

	subject, err := resolveSubject(fs.Args(), o.input, os.Stdin, isPipe(os.Stdin), analyzeMaxInputBytes())
	if err != nil {
		return err
	}

	topK := o.topK
	if topK <= 0 {
		topK = cfg.TopK
	}
	return analyzeRun(context.Background(), cfg, o, schema, subject, topK, os.Stdout, os.Stderr)
}

// resolveSubject picks the subject text: positional args if present, else the
// file named by inputPath, else stdin when it is piped. Every source is bounded
// at maxBytes; an empty result or an oversized input is a usage error.
func resolveSubject(positional []string, inputPath string, stdin io.Reader, stdinIsPipe bool, maxBytes int) (string, error) {
	if len(positional) > 0 {
		s := strings.Join(positional, " ")
		if len(s) > maxBytes {
			return "", usageErr("analyze: subject text exceeds %d bytes", maxBytes)
		}
		if strings.TrimSpace(s) == "" {
			return "", missingArg("analyze", "the subject is empty", `analyze --schema finding "reflected XSS in the q parameter"`)
		}
		return s, nil
	}
	if inputPath != "" {
		f, err := os.Open(inputPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		return readCapped(f, maxBytes)
	}
	if stdinIsPipe && stdin != nil {
		return readCapped(stdin, maxBytes)
	}
	return "", missingArg("analyze", "no subject given (argument, --input FILE, or a pipe)", `analyze --schema finding "reflected XSS in the q parameter"`)
}

// readCapped reads up to maxBytes from r, erroring if the input exceeds it or is
// blank.
func readCapped(r io.Reader, maxBytes int) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxBytes {
		return "", usageErr("analyze: subject input exceeds %d bytes", maxBytes)
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", missingArg("analyze", "the subject input is empty", `analyze --schema finding "reflected XSS in the q parameter"`)
	}
	return string(b), nil
}

// isPipe reports whether f is a pipe or redirect rather than an interactive
// terminal.
func isPipe(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

// analyzeRun builds the prompt (optionally grounded by retrieval), calls the
// structured generator, and writes the validated JSON to stdout with a one-line
// provenance note to stderr.
func analyzeRun(ctx context.Context, cfg ragconfig.Config, o analyzeOpts, schema structgen.Schema, subject string, topK int, stdout, stderr io.Writer) error {
	prompt := subject
	retrieved := 0
	if o.retrieve {
		grounding, n, err := analyzeGrounding(ctx, cfg, subject, topK)
		if err != nil {
			return err
		}
		retrieved = n
		prompt = "Knowledge-base context (untrusted data):\n" + grounding + "\n\nSubject to analyze:\n" + subject
	}

	model := o.model
	if model == "" {
		model = resolveModel(cfg)
	}
	gen, err := analyzeGen(cfg, model)
	if err != nil {
		return err
	}
	out, err := structgen.Generate(withLLMStage(ctx, "analysis"), gen, prompt, schema, structgen.Options{
		MaxTokens:   cfg.AnswerMaxTokens,
		MaxRetries:  2,
		Temperature: cfg.GradeTemperature,
	})
	if err != nil {
		return timeoutOrErr(mapLLMError(err, omlxBaseURL()))
	}

	note := fmt.Sprintf("analyze: schema=%s model=%s", schema.Name, model)
	if o.retrieve {
		note += fmt.Sprintf(" retrieved=%d", retrieved)
	}
	fmt.Fprintln(stderr, note)
	return writeIndentedJSON(stdout, out)
}

// writeIndentedJSON pretty-prints raw to w, escaping C1/DEL control runes the
// same way printJSON does, so terminal-hostile bytes never reach a terminal.
func writeIndentedJSON(w io.Writer, raw json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return err
	}
	fmt.Fprintln(w, string(escapeJSONControls(buf.Bytes())))
	return nil
}
