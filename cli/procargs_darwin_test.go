package main

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// procargsBuf builds a kern.procargs2 buffer: argc, the executable path, NUL
// padding up to the next 8-byte boundary, the arguments, then env.
func procargsBuf(exe string, args []string, env ...string) []byte {
	b := binary.NativeEndian.AppendUint32(nil, uint32(len(args)))
	b = append(append(b, exe...), 0)
	for (len(b)-4)%8 != 0 {
		b = append(b, 0)
	}
	for _, s := range append(append([]string{}, args...), env...) {
		b = append(append(b, s...), 0)
	}
	return b
}

// Empty arguments are kept: an empty argv[0] does not let the next argument
// and the first environment string shift into its place.
func TestParseProcargsKeepsEmptyArguments(t *testing.T) {
	const py = "/r/.venv/bin/python"
	for _, exe := range []string{py, "/r/.venv/bin/pytho", "/r/.venv/bin/pyth", "/r/.venv/bin/python3.12"} {
		for _, args := range [][]string{
			{"", py, "-m"},
			{py, "", "-m"},
			{py, "-m", "blkchain.embed_server"},
			{"", "", ""},
		} {
			gotExe, got, err := parseProcargs(procargsBuf(exe, args, "blkchain.embed_server", "HOME=/x"))
			if err != nil || gotExe != exe || !reflect.DeepEqual(got, args) {
				t.Errorf("exe %q args %q: parsed %q %q (%v)", exe, args, gotExe, got, err)
			}
		}
	}
	for _, bad := range [][]byte{nil, {1, 0}, procargsBuf("/x", []string{"a", "b"})[:12]} {
		if _, _, err := parseProcargs(bad); err == nil {
			t.Errorf("parseProcargs(%q) = nil error, want one", bad)
		}
	}
}
