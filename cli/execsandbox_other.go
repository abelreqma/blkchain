//go:build !darwin

package main

import (
	"context"
	"errors"
	"os/exec"
)

func newSandboxedCommand(ctx context.Context, binary string, args []string, scratch string) (*exec.Cmd, func() error, bool, error) {
	egress, err := resolveExecutorEgress(ctx, binary, args)
	if err != nil {
		return nil, nil, false, err
	}
	if len(egress.IPs) == 0 {
		return nil, nil, false, errors.New("local host executor sandbox is unavailable on this operating system")
	}
	cmd, cleanup, err := newContainerCommand(ctx, binary, args, scratch, egress)
	return cmd, cleanup, true, err
}
