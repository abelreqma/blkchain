package main

import (
	"blkchain/cli/internal/secgate"
	"context"
	"errors"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"os/signal"
	"strings"
	"time"
)

type webDoneMsg struct {
	Output string
	Err    error
}

func webArguments(s string) ([]string, error) {
	if len(s) > 64<<10 {
		return nil, errors.New("web command input limit")
	}
	args := []string{}
	var b strings.Builder
	quote := rune(0)
	escape := false
	started := false
	for _, r := range s {
		if escape {
			b.WriteRune(r)
			escape = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escape = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if r == ' ' || r == '\t' {
			if started {
				args = append(args, b.String())
				b.Reset()
				started = false
			}
			continue
		}
		b.WriteRune(r)
		started = true
	}
	if quote != 0 || escape {
		return nil, errors.New("unterminated quote or escape")
	}
	if started {
		args = append(args, b.String())
	}
	return args, nil
}
func (m model) dispatchWeb(arg, echo string) (tea.Model, tea.Cmd) {
	args, e := webArguments(arg)
	if e != nil {
		return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(e)))
	}
	ctx, cancel := context.WithCancel(context.Background())
	if m.prog != nil {
		ctx = context.WithValue(ctx, webFindingSinkKey{}, func(data []byte) error { m.prog.Send(webFindingMsg{Data: string(data)}); return nil })
	}
	m.cancel = cancel
	m.working = true
	m.tickGen++
	m.workingVerb = "analyzing web..."
	m.turnStart = time.Now()
	m.live = ""
	mode := m.engageMode
	confirm := releaseConfirmer{prog: m.prog, stop: cancel}
	width := m.renderWidth()
	cmd := func() tea.Msg { out, e := webExecute(ctx, args, mode, confirm, true, width); return webDoneMsg{out, e} }
	return m, tea.Batch(tea.Println(echo), m.workTick(), cmd)
}
func replWeb(arg string) error {
	args, e := webArguments(arg)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var confirm secgate.Confirmer
	if isTerminalFile(os.Stdin) {
		confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
	}
	out, e := webExecute(ctx, args, secgate.Safe, confirm, true, 100)
	if out != "" {
		fmt.Print(out)
	}
	return e
}
