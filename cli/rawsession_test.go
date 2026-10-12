package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRawBrokerRetainsShellAcrossControlConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	broker, err := newRawBroker(ctx, 0, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if !strings.HasPrefix(broker.ShellAddr(), "127.0.0.1:") || !strings.HasPrefix(broker.ControlAddr(), "127.0.0.1:") {
		t.Fatalf("raw broker is not loopback-only: shell=%s control=%s", broker.ShellAddr(), broker.ControlAddr())
	}
	var commands atomic.Int32
	ready := make(chan error, 1)
	go func() {
		conn, dialErr := net.Dial("tcp", broker.ShellAddr())
		if dialErr != nil {
			ready <- dialErr
			return
		}
		defer conn.Close()
		ready <- nil
		reader := bufio.NewReader(conn)
		marker := regexp.MustCompile(`([0-9a-f]{32}):START`)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			match := marker.FindStringSubmatch(line)
			if len(match) != 2 {
				return
			}
			commands.Add(1)
			_, _ = fmt.Fprintf(conn, "banner\n\x1e%s:START\x1ehello\x1e%s:END:0\x1e", match[1], match[1])
		}
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	if err := broker.WaitConnected(ctx); err != nil {
		t.Fatal(err)
	}
	if connected, err := rawBrokerStatus(ctx, broker.ControlAddr(), broker.Token()); err != nil || !connected {
		t.Fatalf("retained shell status connected=%t err=%v", connected, err)
	}
	for i := 0; i < 2; i++ {
		response, err := rawBrokerRequest(ctx, broker.ControlAddr(), broker.Token(), []string{"printf", "hello"}, 4096, 3*time.Second)
		if err != nil || response.Output != "hello" || response.ExitCode != 0 {
			t.Fatalf("control connection %d: response=%+v err=%v", i, response, err)
		}
	}
	if commands.Load() != 2 {
		t.Fatalf("retained shell saw %d commands, want 2", commands.Load())
	}
	if _, err := rawBrokerRequest(ctx, broker.ControlAddr(), "wrong-token", []string{"printf", "hello"}, 4096, time.Second); err == nil || commands.Load() != 2 {
		t.Fatal("unauthenticated control request reached the shell")
	}
	if err := rawBrokerClose(ctx, broker.ControlAddr(), broker.Token()); err != nil {
		t.Fatal(err)
	}
	if connected, err := rawBrokerStatus(ctx, broker.ControlAddr(), broker.Token()); err == nil || connected {
		t.Fatal("closed raw broker remained reachable")
	}
}

func TestRawBrokerPOSIXShellFixture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	broker, err := newRawBroker(ctx, 0, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	conn, err := net.Dial("tcp", broker.ShellAddr())
	if err != nil {
		t.Fatal(err)
	}
	shell := exec.CommandContext(ctx, "/bin/sh")
	shell.Stdin, shell.Stdout, shell.Stderr = conn, conn, conn
	if err := shell.Start(); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
		_ = shell.Wait()
	}()
	if err := broker.WaitConnected(ctx); err != nil {
		t.Fatal(err)
	}
	response, err := rawBrokerRequest(ctx, broker.ControlAddr(), broker.Token(), []string{"printf", "a b;$(id)"}, 4096, 3*time.Second)
	if err != nil || response.Output != "a b;$(id)" || response.ExitCode != 0 {
		t.Fatalf("POSIX shell command boundaries failed: response=%+v err=%v", response, err)
	}
	response, err = rawBrokerRequestPipeline(ctx, broker.ControlAddr(), broker.Token(), [][]string{{"printf", "a\nb\n"}, {"grep", "b"}}, 4096, 3*time.Second)
	if err != nil || response.Output != "b\n" || response.ExitCode != 0 {
		t.Fatalf("POSIX shell pipeline failed: response=%+v err=%v", response, err)
	}
}
