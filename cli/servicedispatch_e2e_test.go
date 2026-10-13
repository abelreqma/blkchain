package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
)

func TestServiceDispatchRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip, _ := startDockerHTTPFixture(t, "service-dispatch", "dispatch-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Inspect http://"+ip+":8080/ and http://dispatch.example.test:8080/ through "+ip, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	args, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"-fsS", "--max-time", "5", "http://" + ip + ":8080/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(args))
	if err != nil || !strings.Contains(out, "dispatch-fixture") {
		t.Fatalf("observed port did not unlock the real worker request: %q %v", out, err)
	}
	resolved, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"--resolve", "dispatch.example.test:8080:" + ip, "-fsS", "--max-time", "5", "http://dispatch.example.test:8080/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(resolved))
	if err != nil || !strings.Contains(out, "dispatch-fixture") {
		t.Fatalf("named virtual host did not reach the observed address: %q %v", out, err)
	}
	closed, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"-fsS", "--max-time", "5", "http://" + ip + ":8081/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(closed))
	if err != nil || !strings.Contains(out, "service dispatch") {
		t.Fatalf("closed port was not stopped at dispatch: %q %v", out, err)
	}
}
