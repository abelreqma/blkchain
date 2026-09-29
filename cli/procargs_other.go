//go:build !darwin

package main

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// procCmdlineMaxBytes caps how much of /proc/<pid>/cmdline is read.
const procCmdlineMaxBytes = 1 << 20

// processArgs returns process pid's executable path and argument vector from
// /proc, where the arguments are NUL-separated and keep their boundaries.
// Where there is no /proc it fails, and nothing is matched or signaled.
func processArgs(pid int) (string, []string, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	exe, err := os.Readlink(dir + "/exe")
	if err != nil {
		return "", nil, err
	}
	f, err := os.Open(dir + "/cmdline")
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, procCmdlineMaxBytes))
	if err != nil {
		return "", nil, err
	}
	return exe, strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00"), nil
}
