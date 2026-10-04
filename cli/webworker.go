package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"blkchain/cli/internal/webanalysis"
)

func runWebWorker() error {
	if err := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: 5, Max: 6}); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		if err := unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{Cur: 2 << 30, Max: 2 << 30}); err != nil {
			return err
		}
	}

	var in webanalysis.Input
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 6<<20))
	if err := dec.Decode(&in); err != nil {
		return errors.New("invalid parser input")
	}
	if len(in.Source) > webanalysis.MaxSource {
		return errors.New("parser source limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := webanalysis.Analyze(ctx, in)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

var webParserSlot = make(chan struct{}, 1)

func webParseWorker(ctx context.Context, in webanalysis.Input) (webanalysis.Result, error) {
	var out webanalysis.Result
	if len(in.Source) > webanalysis.MaxSource {
		return out, errors.New("parser source limit")
	}
	select {
	case webParserSlot <- struct{}{}:
		defer func() { <-webParserSlot }()
	case <-ctx.Done():
		return out, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return out, err
	}
	data, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	cmd := exec.CommandContext(ctx, exe, "__web-analysis-worker")
	cmd.Env = []string{"GOMEMLIMIT=128MiB", "GOMAXPROCS=1", "PATH=/usr/bin:/bin"}
	cmd.Dir = os.TempDir()
	cmd.Stdin = bytes.NewReader(data)
	stdout, stderr := &webLimitedBuffer{limit: 16 << 20}, &webLimitedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err = cmd.Run(); err != nil {
		return out, errors.New("parser worker failed or exceeded time/output limit")
	}
	if err = json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return out, errors.New("invalid parser result")
	}
	return out, nil
}
