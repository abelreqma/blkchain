package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/secgate"
)

// terminalConfirmer prompts on out for a y/n approval of each command, reading from in.
type terminalConfirmer struct {
	in  *bufio.Reader
	out io.Writer
}

func newTerminalConfirmer(in io.Reader, out io.Writer) *terminalConfirmer {
	return &terminalConfirmer{in: bufio.NewReader(in), out: out}
}

// Confirm prompts for a y/n approval; only y/yes confirms; EOF or anything else denies.
// Each token is quoted so control characters in model-supplied args cannot alter the prompt.
func (c *terminalConfirmer) Confirm(ctx context.Context, cmd secgate.Command) bool {
	parts := make([]string, 0, len(cmd.Args)+1)
	parts = append(parts, strconv.QuoteToASCII(cmd.Binary))
	for _, a := range cmd.Args {
		parts = append(parts, strconv.QuoteToASCII(a))
	}
	fmt.Fprintf(c.out, "run command: %s\napprove? [y/N]: ", strings.Join(parts, " "))
	line, err := c.in.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// terminalAsker prompts on out for a clarification and reads a line from in.
type terminalAsker struct {
	in  *bufio.Reader
	out io.Writer
}

func newTerminalAsker(in io.Reader, out io.Writer) *terminalAsker {
	return &terminalAsker{in: bufio.NewReader(in), out: out}
}

// Ask prompts for a clarification; empty or EOF cancels. A line matching an
// option label or value returns that value; otherwise, when AllowCustom, the
// line is the custom answer.
func (a *terminalAsker) Ask(ctx context.Context, c askuser.Clarification) askuser.ClarifyResult {
	fmt.Fprintf(a.out, "%s\n", c.Question)
	if c.Detail != "" {
		fmt.Fprintf(a.out, "%s\n", c.Detail)
	}
	for i, o := range c.Options {
		fmt.Fprintf(a.out, "  %d) %s", i+1, o.Label)
		if o.Note != "" {
			fmt.Fprintf(a.out, " - %s", o.Note)
		}
		fmt.Fprintln(a.out)
	}
	fmt.Fprint(a.out, "> ")
	line, err := a.in.ReadString('\n')
	if err != nil && line == "" {
		return askuser.ClarifyResult{Canceled: true}
	}
	ans := strings.TrimSpace(line)
	if ans == "" {
		return askuser.ClarifyResult{Canceled: true}
	}
	for _, o := range c.Options {
		if strings.EqualFold(ans, o.Label) || ans == o.Value {
			return askuser.ClarifyResult{Value: o.Value}
		}
	}
	if c.AllowCustom {
		return askuser.ClarifyResult{Custom: ans}
	}
	// No match and no custom allowed: treat as canceled.
	return askuser.ClarifyResult{Canceled: true}
}
