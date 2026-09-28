package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// knownLogs are the service log basenames written under <root>/.run.
var knownLogs = []string{"api", "embed_server"}

// runLogs prints (or follows) a service log from <root>/.run/<name>.log.
//
//	blk logs            tail the api log
//	blk logs embed_server -n 100
//	blk logs api -f      follow (like tail -f)
func runLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	follow := fs.Bool("f", false, "follow the log (like tail -f)")
	n := fs.Int("n", 40, "number of trailing lines to show")
	if err := fs.Parse(reorder(args, map[string]bool{"n": true})); err != nil {
		return err
	}

	name := "api"
	if fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	if !validLogName(name) {
		return fmt.Errorf("logs: unknown service %q (known: %s)", name, strings.Join(knownLogs, ", "))
	}

	root, err := projectRoot()
	if err != nil {
		return err
	}
	logPath := filepath.Join(root, ".run", name+".log")
	if _, err := os.Stat(logPath); err != nil {
		return fmt.Errorf("logs: no log at %s — is the service running? try `blk up`", logPath)
	}

	if *follow {
		// Delegate following to tail(1): correct rotation handling for free.
		c := exec.Command("tail", "-n", fmt.Sprint(*n), "-f", logPath)
		c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
		return c.Run()
	}

	lines, err := lastLines(logPath, *n)
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

// validLogName reports whether name is a known service log.
func validLogName(name string) bool {
	for _, k := range knownLogs {
		if k == name {
			return true
		}
	}
	return false
}

// lastLines returns the final n lines of the file at path. It reads the whole
// file (service logs are small and rotated by the stack), keeping only a ring
// of the last n lines so memory stays bounded regardless of file size.
func lastLines(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ring := make([]string, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // tolerate long log lines
	for sc.Scan() {
		if len(ring) == n {
			ring = ring[1:]
		}
		ring = append(ring, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ring, nil
}
