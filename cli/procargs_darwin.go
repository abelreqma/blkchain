package main

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// processArgs returns process pid's executable path and argument vector from
// kern.procargs2, which keeps each argument separate (unlike ps, which joins
// them with spaces).
func processArgs(pid int) (string, []string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", nil, err
	}
	return parseProcargs(buf)
}

// parseProcargs parses a kern.procargs2 buffer: argc, the NUL-terminated
// executable path, NUL padding that ends on an 8-byte boundary counted from
// the path's start, then argc NUL-terminated arguments. Only the padding is
// skipped, so an empty argument is kept in its place.
func parseProcargs(buf []byte) (string, []string, error) {
	if len(buf) < 4 {
		return "", nil, errors.New("procargs2: short buffer")
	}
	argc := int(binary.NativeEndian.Uint32(buf))
	rest := buf[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", nil, errors.New("procargs2: no executable path")
	}
	exe := string(rest[:end])
	start := (end + 1 + 7) &^ 7
	if start > len(rest) || len(bytes.Trim(rest[end:start], "\x00")) != 0 {
		return "", nil, errors.New("procargs2: bad padding")
	}
	rest = rest[start:]
	if argc > len(rest) {
		return "", nil, errors.New("procargs2: truncated arguments")
	}
	args := make([]string, 0, argc)
	for len(args) < argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return "", nil, errors.New("procargs2: truncated arguments")
		}
		args = append(args, string(rest[:end]))
		rest = rest[end+1:]
	}
	return exe, args, nil
}
