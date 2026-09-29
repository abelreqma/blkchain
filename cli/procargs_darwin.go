package main

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// processArgs returns process pid's argument vector from kern.procargs2, which
// keeps each argument separate (unlike ps, which joins them with spaces). The
// buffer is argc, the executable path, NUL padding, then argc NUL-terminated
// arguments.
func processArgs(pid int) ([]string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, errors.New("procargs2: short buffer")
	}
	argc := int(binary.NativeEndian.Uint32(buf))
	rest := buf[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return nil, errors.New("procargs2: no executable path")
	}
	rest = bytes.TrimLeft(rest[end:], "\x00")
	var args []string
	for len(args) < argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, errors.New("procargs2: truncated arguments")
		}
		args = append(args, string(rest[:end]))
		rest = rest[end+1:]
	}
	return args, nil
}
