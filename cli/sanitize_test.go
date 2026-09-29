package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"blkchain/cli/internal/client"
)

func TestSanitizeTerminal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii", "hello world", "hello world"},
		{"empty", "", ""},
		{"utf8 cjk", "\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8", "\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8"},
		{"utf8 accents", "caf\u00e9 na\u00efve \u00fcber", "caf\u00e9 na\u00efve \u00fcber"},
		{"utf8 nbsp untouched", "a\u00a0b", "a\u00a0b"},
		{"sgr color", "\x1b[31mred\x1b[0m text", "red text"},
		{"sgr truecolor", "\x1b[38;2;1;2;3mx\x1b[0m", "x"},
		{"csi 2J", "before\x1b[2Jafter", "beforeafter"},
		{"csi cursor home", "a\x1b[Hb", "ab"},
		{"csi with intermediate", "a\x1b[?25lb", "ab"},
		{"osc 0 bel", "a\x1b]0;pwned title\x07b", "ab"},
		{"osc 52 st", "a\x1b]52;c;cHduZWQ=\x1b\\b", "ab"},
		{"osc 8 hyperlink keeps text", "\x1b]8;;https://evil.example/\x1b\\click me\x1b]8;;\x1b\\", "click me"},
		{"osc 8 bel keeps text", "\x1b]8;;https://evil.example/\x07link\x1b]8;;\x07", "link"},
		{"dcs", "a\x1bPqpayload\x1b\\b", "ab"},
		{"sos pm apc", "a\x1bXsos\x1b\\b\x1b^pm\x1b\\c\x1b_apc\x1b\\d", "abcd"},
		{"two byte esc", "a\x1bcb\x1b7c\x1b=d", "abcd"},
		{"charset select", "a\x1b(Bb", "ab"},
		{"c1 csi", "a\u009b2Jb", "ab"},
		{"c1 csi sgr", "a\u009b31mred\u009b0m", "ared"},
		{"c1 osc bel", "a\u009d0;title\x07b", "ab"},
		{"c1 osc st", "a\u009d52;c;xx\u009cb", "ab"},
		{"c1 dcs", "a\u0090payload\x1b\\b", "ab"},
		{"c1 lone", "a\u0085b\u0090", "ab"},
		{"raw invalid c1 byte", "a\x9bb", "ab"},
		{"unterminated csi", "keep\x1b[31", "keep"},
		{"unterminated csi bare", "keep\x1b[", "keep"},
		{"unterminated osc", "keep\x1b]0;title with no end", "keep"},
		{"unterminated dcs", "keep\x1bPabc\x1b", "keep"},
		{"lone esc at end", "keep\x1b", "keep"},
		{"unterminated c1 osc", "keep\u009d0;t", "keep"},
		{"osc aborted by new esc", "a\x1b]0;x\x1b[31mred", "ared"},
		{"crlf to lf", "a\r\nb\r\n", "a\nb\n"},
		{"bare cr", "a\rb", "ab"},
		{"bel", "a\x07b", "ab"},
		{"backspace", "a\x08b", "ab"},
		{"nul", "a\x00b", "ab"},
		{"del", "a\x7fb", "ab"},
		{"other c0", "a\x01\x02\x0b\x0c\x0e\x1fb", "ab"},
		{"keeps newline and tab", "a\n\tb", "a\n\tb"},
		{"esc before newline", "a\x1b\nb", "a\nb"},
		{"mixed", "\x1b[2J\x1b]0;x\x07# Title\r\n\x1b[1mbold\x1b[0m\t\x08ok\n", "# Title\nbold\tok\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeTerminal(tc.in); got != tc.want {
				t.Errorf("sanitizeTerminal(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSanitizeTerminalInvariant checks that no output ever holds an ESC, a C0
// control other than \n and \t, DEL, or a C1 rune, whatever the input.
func TestSanitizeTerminalInvariant(t *testing.T) {
	seeds := []string{
		"\x1b[", "\x1b]", "\x1bP", "\x1b\\", "\u009b", "\u009d", "\x9b", "\x1b", "\x07", "\r",
		"31m", "0;x", "abc", "\n", "\t", "\u00c2", "\xc2", "\u65e5",
	}
	// Every pair and triple of seeds.
	for _, a := range seeds {
		for _, b := range seeds {
			for _, c := range seeds {
				out := sanitizeTerminal(a + b + c)
				for i := 0; i < len(out); {
					r, n := utf8.DecodeRuneInString(out[i:])
					bad := r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || (r >= 0x80 && r <= 0x9f)
					if r == utf8.RuneError && n == 1 {
						bad = out[i] >= 0x80 && out[i] <= 0x9f // raw C1 byte of invalid UTF-8
					}
					if bad {
						t.Fatalf("sanitizeTerminal(%q) = %q holds a control at byte %d", a+b+c, out, i)
					}
					i += n
				}
			}
		}
	}
}

func TestSanitizeTerminalLinear(t *testing.T) {
	inputs := map[string]string{
		"csi":      strings.Repeat("\x1b[", 512<<10),
		"osc":      strings.Repeat("\x1b]", 512<<10),
		"osc body": "\x1b]0;" + strings.Repeat("a", 1<<20),
		"esc":      strings.Repeat("\x1b", 1<<20),
		"c1":       strings.Repeat("\u009b", 512<<10),
		"params":   "\x1b[" + strings.Repeat("1;", 512<<10),
		"text":     strings.Repeat("plain text\n", 100000),
	}
	for name, in := range inputs {
		start := time.Now()
		out := sanitizeTerminal(in)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: sanitizeTerminal took %s on %d bytes", name, d, len(in))
		}
		if strings.ContainsRune(out, 0x1b) {
			t.Errorf("%s: output still holds ESC", name)
		}
	}
}

func TestSanitizeTerminalAllocations(t *testing.T) {
	clean := "no control characters here, just text \u65e5\u672c\u8a9e\n\ttabbed"
	if got := testing.AllocsPerRun(50, func() { _ = sanitizeTerminal(clean) }); got != 0 {
		t.Errorf("clean input allocated %v times, want 0", got)
	}
	if sanitizeTerminal(clean) != clean {
		t.Error("clean input was modified")
	}
	dirty := "text \x1b[31mred\x1b[0m and \x1b]0;t\x07 more \r\n text"
	if got := testing.AllocsPerRun(50, func() { _ = sanitizeTerminal(dirty) }); got > 1 {
		t.Errorf("dirty input allocated %v times, want at most 1", got)
	}
}

// TestTermStreamSplitSequences feeds an escape sequence split at every byte
// boundary and checks that nothing but the visible text comes out.
func TestTermStreamSplitSequences(t *testing.T) {
	inputs := []struct {
		name string
		in   string
		want string
	}{
		{"osc bel", "before\x1b]0;pwned title\x07after", "beforeafter"},
		{"osc st", "before\x1b]52;c;cHduZWQ=\x1b\\after", "beforeafter"},
		{"csi", "before\x1b[2Jafter", "beforeafter"},
		{"sgr", "before\x1b[31mred\x1b[0mafter", "beforeredafter"},
		{"c1 csi", "before\u009b2Jafter", "beforeafter"},
		{"c1 osc", "before\u009d0;t\x07after", "beforeafter"},
		{"multibyte text", "\u65e5\u672c\u8a9e caf\u00e9", "\u65e5\u672c\u8a9e caf\u00e9"},
	}
	for _, tc := range inputs {
		for cut := 0; cut <= len(tc.in); cut++ {
			var ts termStream
			got := ts.Write(tc.in[:cut]) + ts.Write(tc.in[cut:])
			if got != tc.want {
				t.Errorf("%s: split at %d: got %q, want %q", tc.name, cut, got, tc.want)
			}
		}
		// One byte at a time.
		var ts termStream
		var b strings.Builder
		for i := 0; i < len(tc.in); i++ {
			b.WriteString(ts.Write(tc.in[i : i+1]))
		}
		if b.String() != tc.want {
			t.Errorf("%s: byte-wise: got %q, want %q", tc.name, b.String(), tc.want)
		}
	}
}

func TestTermStreamUnterminatedIsDropped(t *testing.T) {
	var ts termStream
	got := ts.Write("keep\x1b]0;never ends")
	if got != "keep" {
		t.Errorf("got %q, want %q", got, "keep")
	}
}

// TestTermStreamBoundsHeldBytes checks that a sequence that never terminates
// does not make the stream hold and rescan an unbounded buffer.
func TestTermStreamBoundsHeldBytes(t *testing.T) {
	var ts termStream
	ts.Write("\x1b]0;")
	var out strings.Builder
	for i := 0; i < 5000; i++ {
		out.WriteString(ts.Write(strings.Repeat("a", 64)))
	}
	if len(ts.pending) > maxHeldSeq+64 {
		t.Errorf("pending grew to %d bytes, cap is %d", len(ts.pending), maxHeldSeq)
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Error("output holds ESC")
	}
}

// TestTermStreamBoundsHeldEscIntermediates covers the ESC + intermediate bytes
// branch: 0x20 is an intermediate, so ESC followed by spaces never reaches a
// final byte and must not be held without bound.
func TestTermStreamBoundsHeldEscIntermediates(t *testing.T) {
	var ts termStream
	var out strings.Builder
	out.WriteString(ts.Write("\x1b"))
	start := time.Now()
	for i := 0; i < 20000; i++ {
		out.WriteString(ts.Write(strings.Repeat(" ", 64)))
		if len(ts.pending) > maxHeldSeq+64 {
			t.Fatalf("pending grew to %d bytes after %d writes, cap is %d", len(ts.pending), i, maxHeldSeq)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("20000 writes took %s", d)
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Error("output holds ESC")
	}
	// One large write is also linear and clean.
	var big termStream
	if got := big.Write("\x1b" + strings.Repeat(" ", 1<<20)); strings.ContainsRune(got, 0x1b) {
		t.Error("large write output holds ESC")
	}
}

func poisonedResults() []client.SearchResult {
	return []client.SearchResult{{
		ID:    "p1",
		Score: 0.9,
		Payload: client.Payload{
			Source:  "src\x1b]0;retitled\x07name",
			Section: "sec\x1b[2Jtion",
			Path:    "corpus/\x1b]52;c;cHduZWQ=\x1b\\file.md",
			Type:    "markdown",
			Text:    "body \x1b[31mred\x1b[0m \x1b]0;x\x07 tail \u009b2J \r\n end",
		},
	}}
}

func TestFormatResultsStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := formatResults("q", poisonedResults(), 5*time.Millisecond, 80)
	if strings.ContainsRune(out, 0x1b) {
		t.Fatalf("formatResults output holds ESC:\n%q", out)
	}
	if strings.ContainsRune(out, 0x9b) || strings.ContainsRune(out, 0x07) || strings.ContainsRune(out, '\r') {
		t.Fatalf("formatResults output holds a control character:\n%q", out)
	}
	for _, want := range []string{"srcname", "section", "file.md", "body red", "tail", "end"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatResults output missing %q:\n%q", want, out)
		}
	}
	if strings.Contains(out, "retitled") || strings.Contains(out, "cHduZWQ") {
		t.Errorf("formatResults kept an escape payload:\n%q", out)
	}
}

func TestFormatAnswerStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	resp := &client.AnswerResponse{
		Answer: "# Title\n\nanswer \x1b]0;retitled\x07text \x1b[2J done",
		Citations: []client.Citation{{
			Source:  "web\x1b]0;x\x07src",
			Path:    "https://evil.example/\x1b[31m",
			Section: "sec\x1b[2J",
		}},
		UsedWeb: true,
	}
	out := formatAnswer(resp, time.Second, 80, false)
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("formatAnswer output holds a control character:\n%q", out)
	}
	if strings.Contains(out, "retitled") {
		t.Errorf("formatAnswer kept an OSC payload:\n%q", out)
	}
	for _, want := range []string{"Title", "answer", "text", "done", "websrc", "evil.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatAnswer output missing %q:\n%q", want, out)
		}
	}
}

func TestGlowRenderStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := glowRender("hello \x1b]52;c;cHduZWQ=\x07 world \x1b[2J", 80)
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("glowRender output holds a control character:\n%q", out)
	}
	if !strings.Contains(out, "hello") || !strings.Contains(out, "world") {
		t.Errorf("glowRender lost the visible text:\n%q", out)
	}
}

func TestPrintSourcesStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := captureStdout(t, func() {
		printSources([]client.Citation{{Source: "a\x1b]0;x\x07b", Path: "p\x1b[2J", Section: "s\x1b[31m"}}, false, false)
	})
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("printSources output holds a control character:\n%q", out)
	}
}

// TestLiveRegionSplitChunk streams an OSC title sequence split across two
// chunkMsgs. The live buffer is sanitized whole at render time, so the split
// cannot leak a partial sequence.
func TestLiveRegionSplitChunk(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	m := model{working: true, width: 80}
	for _, chunk := range []string{"hello \x1b", "]0;pwned\x07 world \x1b[", "2J done"} {
		nm, _ := m.Update(chunkMsg(chunk))
		m = nm.(model)
		lr := m.liveRegion(0)
		if strings.ContainsRune(lr, 0x1b) || strings.ContainsRune(lr, 0x07) {
			t.Fatalf("liveRegion holds a control character after %q:\n%q", chunk, lr)
		}
	}
	lr := m.liveRegion(0)
	if strings.Contains(lr, "pwned") || strings.Contains(lr, "2J") {
		t.Errorf("liveRegion kept an escape payload:\n%q", lr)
	}
	if !strings.Contains(lr, "hello") || !strings.Contains(lr, "world") || !strings.Contains(lr, "done") {
		t.Errorf("liveRegion lost the visible text:\n%q", lr)
	}
	// The buffer itself stays raw: only the display path changes.
	if !strings.Contains(m.live, "\x1b]0;pwned\x07") {
		t.Errorf("live buffer was altered: %q", m.live)
	}
}

func TestPromptEchoStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := promptEcho("line1 \x1b]0;x\x07\nline2 \x1b[2J")
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("promptEcho output holds a control character:\n%q", out)
	}
}

func TestResumeRowStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	item := resumeItem{meta: sessionMeta{ID: "id", Title: "t\x1b]0;x\x07itle"}}
	for _, selected := range []bool{true, false} {
		if row := resumeRow(selected, item); strings.ContainsRune(row, 0x1b) || strings.ContainsRune(row, 0x07) {
			t.Errorf("resumeRow(selected=%v) holds a control character: %q", selected, row)
		}
	}
}

func TestStyleErrStripsControlSequences(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := styleErr(&testErr{"server said \x1b]0;x\x07 no"})
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("styleErr output holds a control character: %q", out)
	}
}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

// TestJSONOutputKeepsPayloadBytes proves --json is not sanitized: the payload
// stays byte-exact in the data. encoding/json escapes ESC and the other C0
// controls as \u00XX, and printJSON escapes DEL and the C1 runes (which
// encoding/json emits raw), so no control byte reaches the terminal.
func TestJSONOutputKeepsPayloadBytes(t *testing.T) {
	resp := client.SearchResponse{Results: poisonedResults()}
	out := captureStdout(t, func() {
		if err := printJSON(resp); err != nil {
			t.Errorf("printJSON: %v", err)
		}
	})
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Errorf("JSON output holds a raw control byte:\n%q", out)
	}
	if !strings.Contains(out, `\u001b`) {
		t.Errorf("JSON output does not carry the ESC as \\u001b:\n%s", out)
	}
	if !strings.Contains(out, `\u0007`) {
		t.Errorf("JSON output does not carry the BEL as \\u0007:\n%s", out)
	}
	if resp.Results[0].Payload.Text != poisonedResults()[0].Payload.Text {
		t.Error("payload text was modified")
	}
}

func TestJSONOutputEscapesC1AndDEL(t *testing.T) {
	text := "a\u009bb\u009dc\x7fd\u0085e\u009f \u65e5\u672c caf\u00e9 \u00a0 \x1b"
	resp := client.SearchResponse{Results: []client.SearchResult{{
		ID: "c1", Payload: client.Payload{Text: text, Source: "\u009d0;x\x07"},
	}}}
	out := captureStdout(t, func() {
		if err := printJSON(resp); err != nil {
			t.Errorf("printJSON: %v", err)
		}
	})
	for _, r := range out {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r < 0x20 && r != '\n') {
			t.Fatalf("JSON output holds raw control rune %U:\n%q", r, out)
		}
	}
	if !strings.Contains(out, "\u65e5\u672c caf\u00e9") {
		t.Errorf("other UTF-8 was altered:\n%q", out)
	}
	var back client.SearchResponse
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got := back.Results[0].Payload.Text; got != text {
		t.Errorf("decoded text = %q, want %q", got, text)
	}
	if got := back.Results[0].Payload.Source; got != "\u009d0;x\x07" {
		t.Errorf("decoded source = %q", got)
	}
}

// TestAskStreamWriterStripsSplitOSC drives the callback runAsk hands to
// AnswerLoop, with an OSC title sequence split across two tokens.
func TestAskStreamWriterStripsSplitOSC(t *testing.T) {
	var full strings.Builder
	out := captureStdout(t, func() {
		stream := newAskStream(os.Stdout, &full)
		for _, tok := range []string{"hello \x1b]0;pw", "ned\x07 wor", "ld \x1b", "[2J done\n"} {
			stream([]byte(tok))
		}
	})
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("stdout holds a control byte: %q", out)
	}
	if out != "hello  world  done\n" {
		t.Errorf("stdout = %q", out)
	}
	if full.String() != out {
		t.Errorf("tracked text %q differs from stdout %q", full.String(), out)
	}
}

func TestSanitizingWriterSplitOSC(t *testing.T) {
	var buf bytes.Buffer
	w := newSanitizingWriter(&buf)
	for _, chunk := range []string{"pre\x1b]0;ev", "il\x07post"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v, want %d, nil", chunk, n, err, len(chunk))
		}
	}
	w.Flush()
	if got := buf.String(); got != "prepost" {
		t.Errorf("output = %q, want %q", got, "prepost")
	}
}

func TestSanitizingWriterPlainPassthrough(t *testing.T) {
	var buf bytes.Buffer
	w := newSanitizingWriter(&buf)
	in := "café 日本語\nline2\ttab"
	// Split inside a multibyte rune to prove the rune is held and rejoined.
	raw := []byte(in)
	cut := strings.Index(in, "é") + 1
	w.Write(raw[:cut])
	w.Write(raw[cut:])
	w.Flush()
	if buf.String() != in {
		t.Errorf("output = %q, want %q", buf.String(), in)
	}
}

func TestSanitizingWriterEmitsWithoutNewline(t *testing.T) {
	var buf bytes.Buffer
	w := newSanitizingWriter(&buf)
	w.Write([]byte("Password: "))
	if buf.String() != "Password: " {
		t.Errorf("prompt held back: got %q before Flush", buf.String())
	}
}

func TestSanitizingWriterFlushDropsPartial(t *testing.T) {
	var buf bytes.Buffer
	w := newSanitizingWriter(&buf)
	w.Write([]byte("keep\x1b]0;never terminated"))
	w.Flush()
	if got := buf.String(); got != "keep" {
		t.Errorf("output = %q, want %q", got, "keep")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSanitizingWriterPropagatesError(t *testing.T) {
	w := newSanitizingWriter(failWriter{})
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("Write to a failing writer returned nil error")
	}
}

func TestRunSanitizedStripsBothStreams(t *testing.T) {
	c := exec.Command("sh", "-c", `printf 'out\033]0;evil\007\033[2Jok\n'; printf 'err\033]52;c;eA==\007fine\n' >&2`)
	var out, errOut bytes.Buffer
	canceled, err := runSanitizedTo(c, &out, &errOut)
	if err != nil || canceled {
		t.Fatalf("runSanitizedTo() = %v, %v, want false, nil", canceled, err)
	}
	if out.String() != "outok\n" || errOut.String() != "errfine\n" {
		t.Errorf("stdout = %q, stderr = %q", out.String(), errOut.String())
	}
}

func TestRunSanitizedReportsExitError(t *testing.T) {
	c := exec.Command("sh", "-c", "exit 3")
	canceled, err := runSanitizedTo(c, io.Discard, io.Discard)
	var ee *exec.ExitError
	if canceled || !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("runSanitizedTo() = %v, %v, want false, exit 3", canceled, err)
	}
}

func TestInterruptedExit(t *testing.T) {
	exit130 := exec.Command("sh", "-c", "exit 130").Run()
	exit1 := exec.Command("sh", "-c", "exit 1").Run()
	sigterm := exec.Command("sh", "-c", "kill -TERM $$").Run()
	type exitCase struct {
		name string
		err  error
		saw  bool
		want bool
	}
	cases := []exitCase{
		{"exit 130 after ctrl+c", exit130, true, true},
		{"plain failure", exit1, true, false},
		{"sigterm", sigterm, true, false},
		{"nil error", nil, true, false},
		{"non exit error", errors.New("boom"), true, false},
	}
	// A child cannot be killed by SIGINT when the test binary runs with it
	// ignored (a background job under a non-interactive sh): children inherit
	// the ignore, so kill -INT does nothing.
	if !sigintIgnoredAtStart {
		sigint := exec.Command("sh", "-c", "kill -INT $$").Run()
		cases = append(cases,
			exitCase{"sigint after ctrl+c", sigint, true, true},
			exitCase{"sigint without ctrl+c", sigint, false, false})
	}
	for _, tc := range cases {
		if got := interruptedExit(tc.err, tc.saw); got != tc.want {
			t.Errorf("%s: interruptedExit() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
