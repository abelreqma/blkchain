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
	return filepath.Join(base, "blkchain", "history"), nil
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

// appendHistory appends one line to the history file, creating its parent
// directory (0755) and the file (0644) if needed. Empty lines and lines
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

	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

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
