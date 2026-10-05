//go:build !darwin

package main

import (
	"context"
	"errors"
	"os/exec"
)

func newSandboxedCommand(context.Context, string, []string, string) (*exec.Cmd, error) {
	return nil, errors.New("executor sandbox is unavailable on this operating system")
}
