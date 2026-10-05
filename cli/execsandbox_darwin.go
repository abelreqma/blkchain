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
(deny network*)
(deny file-read*)
(allow file-read*
  (literal "/")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/usr/bin")
  (subpath "/usr/sbin")
  (subpath "/usr/lib")
  (subpath "/usr/libexec")
  (subpath "/usr/share")
  (subpath "/System/Library")
  (subpath "/System/Cryptexes")
  (literal "/dev/null")
  (literal "/dev/urandom")
  (literal "/dev/random")
  (literal "/dev/zero")
  (subpath (param "SCRATCH"))
  (subpath (param "SCRATCH_ALIAS")))
(deny file-read* (subpath "/System/Volumes/Data"))
(allow file-read-metadata
  (literal "/var")
  (literal "/private")
  (literal "/private/var")
  (subpath "/private/var/folders"))
(deny file-write*)
(allow file-write* (subpath (param "SCRATCH")) (subpath (param "SCRATCH_ALIAS")))`

func newSandboxedCommand(ctx context.Context, binary string, args []string, scratch string) (*exec.Cmd, func() error, bool, error) {
	if scratch == "" {
		return nil, nil, false, errors.New("executor scratch directory is required")
	}
	alias, err := filepath.Abs(scratch)
	if err != nil {
		return nil, nil, false, err
	}
	root, err := filepath.EvalSymlinks(scratch)
	if err != nil {
		return nil, nil, false, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, false, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, false, fmt.Errorf("executor scratch directory must be private (mode %o, directory %t)", info.Mode().Perm(), info.IsDir())
	}
	egress, err := resolveExecutorEgress(ctx, binary, args)
	if err != nil {
		return nil, nil, false, err
	}
	if len(egress.IPs) > 0 {
		cmd, cleanup, err := newContainerCommand(ctx, binary, args, root, egress)
		return cmd, cleanup, true, err
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, nil, false, err
	}
	commandArgs := append([]string{"-D", "SCRATCH=" + root, "-D", "SCRATCH_ALIAS=" + alias, "-p", executorSandboxProfile, resolved}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", commandArgs...)
	cmd.Dir = root
	return cmd, func() error { return nil }, false, nil
}
