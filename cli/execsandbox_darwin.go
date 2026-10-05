package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const executorSandboxProfile = `(version 1)
(allow default)
(deny file-read*)
(allow file-read*
  (literal "/")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/usr")
  (subpath "/System")
  (subpath "/Library")
  (subpath "/dev")
  (subpath "/private/etc")
  (subpath "/private/var/db")
  (subpath "/opt/homebrew")
  (subpath "/usr/local")
  (subpath (param "SCRATCH"))
  (subpath (param "SCRATCH_ALIAS")))
(allow file-read-metadata
  (literal "/var")
  (literal "/private")
  (literal "/private/var")
  (subpath "/private/var/folders"))
(deny file-write*)
(allow file-write* (subpath (param "SCRATCH")) (subpath (param "SCRATCH_ALIAS")))`

func newSandboxedCommand(ctx context.Context, binary string, args []string, scratch string) (*exec.Cmd, error) {
	if scratch == "" {
		return nil, errors.New("executor scratch directory is required")
	}
	alias, err := filepath.Abs(scratch)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(scratch)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("executor scratch directory must be private (mode %o, directory %t)", info.Mode().Perm(), info.IsDir())
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, err
	}
	commandArgs := append([]string{"-D", "SCRATCH=" + root, "-D", "SCRATCH_ALIAS=" + alias, "-p", executorSandboxProfile, resolved}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", commandArgs...)
	cmd.Dir = root
	return cmd, nil
}
