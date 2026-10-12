package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type footholdConn struct {
	net.Conn
	once  sync.Once
	close func()
}

func (c *footholdConn) Close() error {
	c.once.Do(c.close)
	return nil
}

func (r *engageRunner) DialFoothold(ctx context.Context, address string) (net.Conn, error) {
	if r == nil || r.foothold == nil {
		return nil, errors.New("foothold carrier unavailable")
	}
	if r.dialFn != nil {
		return r.dialFn(ctx, address)
	}
	if r.pivotSlots == nil {
		return nil, errors.New("foothold stream budget unavailable")
	}
	argv, err := r.foothold.DialArgs(address)
	if err != nil {
		return nil, err
	}
	select {
	case r.pivotSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-r.pivotSlots }
	worker, err := r.worker(ctx, "web-pivot", false)
	if err != nil {
		release()
		return nil, err
	}
	args := append([]string{"exec", "-i", "--user", "1000:1000", worker}, argv...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		release()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		release()
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &cappedWriter{cap: 4096, buf: &stderr}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		release()
		return nil, errors.New("foothold stream could not start")
	}
	client, bridge := net.Pipe()
	conn := &footholdConn{Conn: client}
	conn.close = func() {
		_ = client.Close()
		_ = bridge.Close()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = cmd.Process.Kill()
	}
	go func() {
		_, _ = io.Copy(stdin, bridge)
		_ = stdin.Close()
	}()
	go func() {
		_, _ = io.Copy(bridge, stdout)
		_ = bridge.Close()
	}()
	go func() {
		_ = cmd.Wait()
		_ = conn.Close()
		release()
	}()
	return conn, nil
}

func (r *engageRunner) LookupFootholdHost(ctx context.Context, host string) ([]net.IP, int, error) {
	if r == nil || r.foothold == nil || len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, " \t\r\n\x00/\\") {
		return nil, 0, errors.New("invalid foothold hostname lookup")
	}
	stages := footholdStages(r.foothold, []pipelineStage{{Binary: "getent", Args: []string{"ahosts", host}}})
	result, outputs := r.Run(ctx, stages, "web-pivot", 8192, 5*time.Second)
	if result.Err != nil || result.TimedOut || len(outputs) != 1 || outputs[0].ExitCode != 0 || outputs[0].Dropped != 0 {
		return nil, 0, errors.New("foothold hostname lookup failed")
	}
	output := outputs[0].Stdout
	if len(output) > 8192 {
		return nil, 0, errors.New("foothold hostname response exceeds limit")
	}
	seen := map[string]bool{}
	var ips []net.IP
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || len(fields) < 3 {
			return nil, 0, errors.New("invalid foothold hostname response")
		}
		if !seen[ip.String()] {
			ips = append(ips, ip)
			seen[ip.String()] = true
			if len(ips) > 16 {
				return nil, 0, errors.New("foothold hostname response exceeds address limit")
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, errors.New("foothold hostname lookup returned no address")
	}
	return ips, len(output), nil
}
