package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// sanitize.go strips terminal control sequences from untrusted text before it
// is rendered. The corpus, web results, LLM output, and replayed sessions are
// all attacker-influenced, and lipgloss and glamour pass escape sequences
// through unchanged, so a chunk could otherwise retitle the window (OSC 0),
// clear the screen (CSI 2J), or write the clipboard (OSC 52).
//
// The guarantee is structural: the output never holds ESC, a C0 control other
// than \n and \t, DEL, or a C1 control (U+0080..U+009F, or a raw 0x80..0x9F
// byte of invalid UTF-8). With no introducer left, nothing in the output can
// start a sequence. The sequence parsing below exists so the payload of a
// stripped sequence (for example "]0;title") does not linger as visible text.

// maxHeldSeq bounds how many bytes of an unterminated sequence a termStream
// holds back waiting for its terminator. Past it the introducer is dropped and
// scanning resumes, so a stream that never terminates cannot grow the buffer
// or make every chunk rescan it.
const maxHeldSeq = 4096

// sanitizeTerminal removes terminal control sequences and control characters
// from s (see the file comment). An unterminated sequence at the end of s is
// dropped. Runs in linear time, allocates at most one buffer, and returns s
// itself when there is nothing to remove.
func sanitizeTerminal(s string) string {
	out, _ := stripTerminal(s, true)
	return out
}

// termStream sanitizes text that arrives in chunks. A sequence can be split
// across chunks (ESC at the end of one, "]0;x" BEL at the start of the next),
// so a trailing incomplete sequence or UTF-8 rune is held back until the next
// Write. Text still held when the stream ends is an unterminated sequence and
// is dropped, so there is nothing to flush.
type termStream struct {
	pending string
}

// Write returns the sanitized text that is now safe to emit.
func (t *termStream) Write(chunk string) string {
	s := chunk
	if t.pending != "" {
		s = t.pending + chunk
	}
	out, n := stripTerminal(s, false)
	t.pending = s[n:]
	return out
}

// sanitizingWriter is an io.Writer that sanitizes a byte stream (a child
// process's stdout or stderr) before it reaches the terminal. Each Write emits
// its clean text immediately, so a prompt with no trailing newline still shows.
type sanitizingWriter struct {
	w  io.Writer
	ts termStream
}

func newSanitizingWriter(w io.Writer) *sanitizingWriter {
	return &sanitizingWriter{w: w}
}

// Write reports len(p) on success: exec.Cmd treats a short count as an error,
// and held-back bytes are not lost, only delayed.
func (s *sanitizingWriter) Write(p []byte) (int, error) {
	if out := s.ts.Write(string(p)); out != "" {
		if _, err := io.WriteString(s.w, out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush ends the stream. Whatever termStream still holds is an unterminated
// sequence or a cut-off rune, so it is dropped, never passed through.
func (s *sanitizingWriter) Flush() {
	s.ts.pending = ""
}

// childDrainWait bounds how long Run waits for output pipes to close after the
// child exits, so a grandchild that inherited them cannot hang blk.
const childDrainWait = 2 * time.Second

// runSanitized runs c with its stdout and stderr relayed to the terminal
// through sanitizing writers. The caller sets c.Stdin. See runSanitizedTo.
func runSanitized(c *exec.Cmd) (canceled bool, err error) {
	return runSanitizedTo(c, os.Stdout, os.Stderr)
}

// runSanitizedTo is runSanitized with explicit destinations. Output streams
// while the child runs. blk catches SIGINT for the duration: the terminal also
// sends it to the child, which can then shut down while blk keeps relaying its
// last output instead of dying first and breaking the pipe. canceled is true,
// with a nil err, when the child ended because the operator pressed ctrl+c.
func runSanitizedTo(c *exec.Cmd, stdout, stderr io.Writer) (canceled bool, err error) {
	so, se := newSanitizingWriter(stdout), newSanitizingWriter(stderr)
	c.Stdout, c.Stderr = so, se
	c.WaitDelay = childDrainWait

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	err = c.Run()
	so.Flush()
	se.Flush()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil // the child exited cleanly, only a pipe holder lingered
	}
	if interruptedExit(err, len(sig) > 0) {
		return true, nil
	}
	return false, err
}

// interruptedExit reports whether err is a child exit caused by SIGINT (killed
// by it, or the conventional exit status 130) after blk itself saw ctrl+c.
func interruptedExit(err error, sawSigint bool) bool {
	var ee *exec.ExitError
	if !sawSigint || !errors.As(err, &ee) {
		return false
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGINT {
		return true
	}
	return ee.ExitCode() == 130
}

// stripTerminal is the shared scanner. With final set, s is the whole input
// and an unterminated sequence is dropped to the end. Without it, a trailing
// incomplete sequence or rune is left unconsumed: the result is the sanitized
// s[:n] and n is the first byte the caller must keep for the next call.
func stripTerminal(s string, final bool) (string, int) {
	var b strings.Builder
	started := false
	last := 0 // s[last:i] is kept text not yet copied to b
	i := 0

	// drop removes s[from:to] from the output.
	drop := func(from, to int) {
		if !started {
			b.Grow(len(s))
			started = true
		}
		b.WriteString(s[last:from])
		last = to
	}

	// seq handles a sequence whose body starts at j. It drops the sequence and
	// returns the next index, or ok=false when the caller must stop and hold
	// s[i:] back.
	seq := func(from, j int, kind seqKind) (next int, ok bool) {
		end, done := scanSeq(s, j, kind)
		if done {
			drop(from, end)
			return end, true
		}
		if final {
			drop(from, len(s))
			return len(s), true
		}
		if len(s)-from > maxHeldSeq {
			drop(from, j) // give up on the terminator, drop only the introducer
			return j, true
		}
		return from, false
	}

scan:
	for i < len(s) {
		c := s[i]
		switch {
		case c == 0x1b:
			if i+1 >= len(s) {
				if final {
					drop(i, len(s))
					i = len(s)
					continue
				}
				break scan
			}
			var kind seqKind
			switch s[i+1] {
			case '[':
				kind = seqCSI
			case ']':
				kind = seqOSC
			case 'P', 'X', '^', '_':
				kind = seqString
			default:
				// Two-byte ESC x, or ESC + intermediates + final (ESC ( B).
				j := i + 1
				for j < len(s) && s[j] >= 0x20 && s[j] <= 0x2f {
					j++
				}
				switch {
				case j < len(s) && s[j] >= 0x30 && s[j] <= 0x7e:
					j++
				case j >= len(s) && !final:
					if len(s)-i > maxHeldSeq {
						j = i + 1 // give up on a final byte, drop only the ESC
					} else {
						break scan
					}
				}
				drop(i, j)
				i = j
				continue
			}
			next, ok := seq(i, i+2, kind)
			if !ok {
				break scan
			}
			i = next
		case c == '\n' || c == '\t':
			i++
		case c < 0x20 || c == 0x7f:
			drop(i, i+1)
			i++
		case c < 0x80:
			i++
		default:
			if !final && !utf8.FullRuneInString(s[i:]) {
				break scan // partial rune, possibly half of a C1 control
			}
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				if c <= 0x9f {
					drop(i, i+1) // raw C1 byte of invalid UTF-8
				}
				i++
				continue
			}
			if r < 0x80 || r > 0x9f {
				i += n
				continue
			}
			var kind seqKind
			switch r {
			case 0x9b:
				kind = seqCSI
			case 0x9d:
				kind = seqOSC
			case 0x90, 0x98, 0x9e, 0x9f:
				kind = seqString
			default:
				drop(i, i+n) // any other C1 control, including a stray ST
				i += n
				continue
			}
			next, ok := seq(i, i+n, kind)
			if !ok {
				break scan
			}
			i = next
		}
	}

	if !started {
		return s[:i], i // nothing dropped: the input itself, no allocation
	}
	b.WriteString(s[last:i])
	return b.String(), i
}

type seqKind int

const (
	seqCSI    seqKind = iota // parameters, intermediates, one final byte
	seqOSC                   // string ended by BEL or ST
	seqString                // DCS, SOS, PM, APC: string ended by ST
)

// scanSeq finds the end of the sequence body that starts at j. It returns the
// index just past the sequence and done=true, or done=false when the input
// ends first.
func scanSeq(s string, j int, kind seqKind) (end int, done bool) {
	if kind == seqCSI {
		for k := j; k < len(s); k++ {
			c := s[k]
			switch {
			case c >= 0x20 && c <= 0x3f:
			case c >= 0x40 && c <= 0x7e:
				return k + 1, true
			default:
				// Not a CSI byte: the sequence is malformed and ends here. The
				// byte is handled by the caller's loop.
				return k, true
			}
		}
		return len(s), false
	}
	for k := j; k < len(s); k++ {
		switch c := s[k]; {
		case c == 0x07 && kind == seqOSC:
			return k + 1, true
		case c == 0x1b:
			if k+1 >= len(s) {
				return len(s), false
			}
			if s[k+1] == '\\' {
				return k + 2, true
			}
			return k, true // a new ESC aborts the string, as terminals do
		case c == 0xc2: // U+009C (ST) is C2 9C in UTF-8
			if k+1 >= len(s) {
				return len(s), false
			}
			if s[k+1] == 0x9c {
				return k + 2, true
			}
		}
	}
	return len(s), false
}
