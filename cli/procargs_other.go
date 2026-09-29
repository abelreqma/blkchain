//go:build !darwin

package main

import (
	"os"
	"strconv"
	"strings"
)

// processArgs returns process pid's argument vector from /proc, where the
// arguments are NUL-separated and keep their boundaries. Where there is no
// /proc it fails, and nothing is matched or signaled.
func processArgs(pid int) ([]string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00"), nil
}
