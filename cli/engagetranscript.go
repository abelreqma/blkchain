package main

import (
	"blkchain/cli/internal/webanalysis"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

var engageTerminalEscapes = regexp.MustCompile("\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)|\x1b\\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")

func terminalSafe(value string) string {
	value = engageTerminalEscapes.ReplaceAllString(value, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, value)
}

type actionRecord struct {
	Stages        int    `json:"stages,omitempty"`
	CapturedBytes int    `json:"captured_bytes,omitempty"`
	ID            string `json:"id"`
	Task          string `json:"task,omitempty"`
	Runner        string `json:"runner"`
	Kind          string `json:"kind"`
	Command       string `json:"command"`
	// Destination is the foothold host a pivoted action ran on, and is empty when
	// the action ran in the sandbox worker. A pivoted action executes outside the
	// guard's firewall, so the evidence records where it ran.
	Destination string `json:"destination,omitempty"`
	Status      string `json:"status"`
	At          string `json:"at"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	ExitCode    int    `json:"exit_code"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	Dropped     int64  `json:"dropped_bytes,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type actionTranscript struct {
	onPersist                       func() error
	orderMu                         sync.Mutex
	mu                              sync.Mutex
	path, mode, runner, otherRunner string
	seq, actions                    int
	maxActions, maxBytes, used      int
	out                             io.Writer
	onEvent                         func(actionRecord)
}

func validTranscriptMode(mode string) bool {
	return mode == "off" || mode == "important" || mode == "full"
}

func newActionTranscript(dir, mode, runner string, maxActions, maxBytes int, out io.Writer) *actionTranscript {
	return &actionTranscript{path: filepath.Join(dir, "actions.jsonl"), mode: mode, runner: runner, maxActions: maxActions, maxBytes: maxBytes, out: out}
}

func (t *actionTranscript) record(rec actionRecord) error {
	if t == nil {
		return nil
	}
	t.orderMu.Lock()
	defer t.orderMu.Unlock()
	return t.recordOrdered(rec)
}

func (t *actionTranscript) recordOrdered(rec actionRecord) error {
	t.mu.Lock()
	rec.Runner = t.runner
	rec.At = time.Now().UTC().Format(time.RFC3339Nano)
	if rec.ID == "" {
		t.seq++
		rec.ID = fmt.Sprintf("a-%06d", t.seq)
	}
	for _, text := range []*string{&rec.Stdout, &rec.Stderr} {
		room := t.maxBytes - t.used
		if room < 0 {
			room = 0
		}
		if len(*text) > room {
			rec.Dropped += int64(len(*text) - room)
			*text = (*text)[:room]
		}
		t.used += len(*text)
		rec.CapturedBytes += len(*text)
	}
	data, err := json.Marshal(rec)
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(t.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, err = f.Write(append(data, '\n'))
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	callback := t.onEvent
	persist := t.onPersist
	mode := t.mode
	t.mu.Unlock()
	if err == nil && persist != nil {
		err = persist()
	}
	if err == nil && t.out != nil && mode != "off" {
		_, err = io.WriteString(t.out, renderActionRecord(rec, mode))
	}
	if err == nil && callback != nil && mode != "off" {
		callback(rec)
	}
	return err
}

func redactEngageText(text string) string {
	lines := strings.Split(terminalSafe(text), "\n")
	for index, line := range lines {
		lines[index] = webanalysis.RedactText(line)
	}
	return strings.Join(lines, "\n")
}

func (t *actionTranscript) restore() error {
	fd, err := syscall.Open(t.path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return errors.New("invalid transcript checkpoint: action log is missing")
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), t.path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<30 {
		return errors.New("invalid transcript checkpoint size or type")
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 128<<20)
	running := map[int]bool{}
	terminal := map[string]bool{}
	for scanner.Scan() {
		if err := uniqueJSONFields(scanner.Bytes()); err != nil {
			return fmt.Errorf("invalid transcript checkpoint: %w", err)
		}
		var rec actionRecord
		dec := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return fmt.Errorf("invalid transcript checkpoint: %w", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return errors.New("invalid transcript checkpoint trailing content")
		}
		parts := strings.Split(strings.TrimPrefix(rec.ID, "a-"), ".")
		if !strings.HasPrefix(rec.ID, "a-") || len(parts) > 2 || len(parts[0]) != 6 {
			return fmt.Errorf("invalid action identity in checkpoint")
		}
		sequence, err := strconv.Atoi(parts[0])
		if err != nil || sequence < 1 || sequence > t.seq+1 || sequence < t.seq && !running[sequence] {
			return fmt.Errorf("invalid action sequence in checkpoint")
		}
		if len(parts) == 2 {
			stage, err := strconv.Atoi(parts[1])
			if err != nil || stage < 1 || stage > 3 || !running[sequence] {
				return fmt.Errorf("invalid pipeline stage in checkpoint")
			}
		}
		if sequence > t.seq {
			t.seq++
		}
		if rec.Runner != t.runner && rec.Runner != t.otherRunner || rec.CapturedBytes != len(rec.Stdout)+len(rec.Stderr) || rec.Dropped < 0 || len(rec.Command) > 256<<10 || len(rec.Reason) > 64<<10 || len(rec.Task) > 256 {
			return fmt.Errorf("invalid action accounting in checkpoint")
		}
		if rec.Status == "running" {
			if len(parts) != 1 || running[sequence] || rec.Stages < 1 || rec.Stages > 3 {
				return fmt.Errorf("invalid checkpoint stage count")
			}
			running[sequence] = true
			t.actions += rec.Stages
		} else if rec.Stages != 0 || rec.Status != "denied" && rec.Status != "allowed" && !running[sequence] || rec.Status != "denied" && rec.Status != "allowed" && rec.Status != "complete" && rec.Status != "failed" && rec.Status != "timeout" && rec.Status != "canceled" {
			return fmt.Errorf("invalid action status in checkpoint")
		} else if (rec.Status == "denied" || rec.Status == "allowed") && (running[sequence] || len(parts) != 1) {
			return fmt.Errorf("invalid policy action in checkpoint")
		} else if terminal[rec.ID] {
			return fmt.Errorf("duplicate terminal action in checkpoint")
		} else {
			terminal[rec.ID] = true
		}
		if rec.CapturedBytes < 0 || rec.CapturedBytes > 64<<20 {
			return fmt.Errorf("invalid checkpoint capture count")
		}
		t.used += rec.CapturedBytes
		if t.actions > t.maxActions || t.used > t.maxBytes {
			return fmt.Errorf("checkpoint exceeds RoE budget")
		}
	}
	return scanner.Err()
}

func renderActionRecord(rec actionRecord, mode string) string {
	var b strings.Builder
	// A pivoted action names its destination, so an operator watching the run
	// sees which commands executed on the foothold rather than in the runner.
	where := ""
	if rec.Destination != "" {
		where = " on " + redactEngageText(rec.Destination)
	}
	fmt.Fprintf(&b, "%s [%s]%s %s %s\n", rec.ID, redactEngageText(rec.Task), where, strings.ToUpper(rec.Status), redactEngageText(rec.Command))
	for _, stream := range []struct{ name, text string }{{"stdout", rec.Stdout}, {"stderr", rec.Stderr}} {
		if stream.text == "" {
			continue
		}
		text := stream.text
		if mode != "full" {
			lines := strings.Split(text, "\n")
			if len(lines) > 24 {
				text = strings.Join(lines[:24], "\n") + "\n[preview truncated; see actions.jsonl]"
			}
			if len(text) > 8192 {
				text = text[:8192] + "\n[preview truncated; see actions.jsonl]"
			}
		}
		fmt.Fprintf(&b, "%s | untrusted\n%s\n", stream.name, redactEngageText(text))
	}
	if rec.Reason != "" {
		fmt.Fprintf(&b, "reason: %s\n", redactEngageText(rec.Reason))
	}
	if rec.Status != "running" && rec.Status != "allowed" && rec.Status != "denied" {
		fmt.Fprintf(&b, "exit=%d duration=%dms dropped=%d bytes\n", rec.ExitCode, rec.DurationMS, rec.Dropped)
	}
	return b.String()
}
