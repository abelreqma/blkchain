package main

import "os"

// colorEnabled is decided once at startup: only when stdout is a real terminal
// and NO_COLOR is unset. In tests (stdout is a pipe) and pipes/files it is off,
// so output stays plain and greppable.
var colorEnabled = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string  { return paint("1", s) }
func dim(s string) string   { return paint("2", s) }
func green(s string) string { return paint("32", s) }
func red(s string) string   { return paint("31", s) }
func cyan(s string) string  { return paint("36", s) }
