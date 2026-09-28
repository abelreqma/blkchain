package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// historyMaxLines caps how many lines loadHistory returns and appendHistory
// retains.
const historyMaxLines = 500

// historyPath returns ~/.config/blkchain/history (honoring XDG_CONFIG_HOME),
// mirroring the pattern in paths.go's configPath.
func historyPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	path := filepath.Join(base, "blkchain", "history")
	if err := privateDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	return path, nil
}

// loadHistory returns the REPL's saved command history, oldest first,
// capped to the last historyMaxLines entries. It returns nil if the history
// file is missing or unreadable.
func loadHistory() []string {
	p, err := historyPath()
	if err != nil {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return nil
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		return nil
	}

	if len(lines) > historyMaxLines {
		lines = lines[len(lines)-historyMaxLines:]
	}
	return lines
}

// appendHistory appends one line to the history file, creating private storage
// for the file if needed. Empty lines and lines
// identical to the last saved entry are skipped.
func appendHistory(line string) error {
	if strings.TrimSpace(line) == "" {
		return nil
	}

	p, err := historyPath()
	if err != nil {
		return err
	}

	if last := lastHistoryLine(p); last == line {
		return nil
	}

	if err := privateDir(filepath.Dir(p)); err != nil {
		return err
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}

	_, err = f.WriteString(line + "\n")
	return err
}

// lastHistoryLine returns the last line of the history file at p, or "" if
// it doesn't exist or is empty.
func lastHistoryLine(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}
