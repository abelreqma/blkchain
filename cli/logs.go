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

// logsOpts holds the flags of `blk logs`.
type logsOpts struct {
	follow bool
	n      int
}

// defineLogsFlags declares `blk logs`'s flags.
func defineLogsFlags(fs *flag.FlagSet, o *logsOpts) {
	fs.BoolVar(&o.follow, "f", false, "keep following the log as it grows (like tail -f)")
	fs.IntVar(&o.n, "n", 40, "show the last `N` lines")
}

// runLogs prints (or follows) a service log from <root>/.run/<name>.log.
//
//	blk logs            tail the api log
//	blk logs embed_server -n 100
//	blk logs api -f      follow (like tail -f)
func runLogs(args []string) error {
	var o logsOpts
	fs := newFlagSet("logs")
	defineLogsFlags(fs, &o)
	if err := parseFlags(fs, reorder(args, map[string]bool{"n": true})); err != nil {
		return err
	}
	follow, n := &o.follow, &o.n

	name := "api"
	if fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	if !validLogName(name) {
		return usageErr(`logs: unknown service %q (known: %s). Example: blk logs api. See "blk help logs".`, name, strings.Join(knownLogs, ", "))
	}

	root, err := projectRoot()
	if err != nil {
		return err
	}
	logPath := filepath.Join(root, ".run", name+".log")
	if _, err := os.Stat(logPath); err != nil {
		return fmt.Errorf("logs: no log at %s, is the service running? try `blk up`", logPath)
	}

	if *follow {
		// Delegate following to tail(1): correct rotation handling for free.
		c := exec.Command("tail", "-n", fmt.Sprint(*n), "-f", logPath)
		c.Stdin = os.Stdin
		// tail -f only ends by ctrl+c, which is not an error.
		_, err := runSanitized(c)
		return err
	}

	lines, err := lastLines(logPath, *n)
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Println(sanitizeTerminal(l))
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
