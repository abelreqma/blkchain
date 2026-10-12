package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
)

func TestFootholdAuthenticatedLocalSSH(t *testing.T) {
	if os.Getenv("BLKCHAIN_LOCAL_SSH_E2E") != "1" {
		t.Skip("requires local OpenSSH server")
	}
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("local OpenSSH server unavailable")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clientKey := filepath.Join(dir, "client")
	hostKey := filepath.Join(dir, "host")
	for _, path := range []string{clientKey, hostKey} {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	clientPub, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), clientPub, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	hostPub, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(hostPub))
	if len(fields) < 2 {
		t.Fatal("invalid fixture host key")
	}
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, []byte(fmt.Sprintf("[127.0.0.1]:%d %s %s\n", port, fields[0], fields[1])), 0600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAllowUsers %s\n", port, hostKey, filepath.Join(dir, "sshd.pid"), filepath.Join(dir, "authorized_keys"), account.Username)
	configPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/sbin/sshd", "-t", "-f", configPath).CombinedOutput(); err != nil {
		t.Fatalf("sshd configuration: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, "/usr/sbin/sshd", "-D", "-e", "-f", configPath)
	var serverLog bytes.Buffer
	server.Stderr = &serverLog
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = server.Wait()
	}()
	carrier, err := newFootholdTransport(&secgate.Foothold{Host: "127.0.0.1", Transport: "ssh", User: account.Username,
		Port: port, Key: clientKey, KnownHosts: known})
	if err != nil {
		t.Fatal(err)
	}
	for i, arg := range carrier.prefix {
		carrier.prefix[i] = strings.ReplaceAll(strings.ReplaceAll(arg, footholdSecretDir+"/key", clientKey), footholdSecretDir+"/known_hosts", known)
	}
	deadline := time.Now().Add(5 * time.Second)
	authenticated := false
	for time.Now().Before(deadline) {
		argv := carrier.Wrap([]string{"printf", "authenticated"})
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
		if err == nil && string(out) == "authenticated" {
			authenticated = true
			break
		}
		if !strings.Contains(string(out), "Connection refused") {
			t.Fatalf("authenticated carrier: %v %s; sshd: %s", err, out, serverLog.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !authenticated {
		t.Fatalf("authenticated carrier did not connect; sshd: %s", serverLog.String())
	}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "through-ssh")
	}))
	defer fixture.Close()
	address := strings.TrimPrefix(fixture.URL, "http://")
	argv, err := carrier.DialArgs(address)
	if err != nil {
		t.Fatal(err)
	}
	stream := exec.CommandContext(ctx, argv[0], argv[1:]...)
	input, err := stream.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := stream.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(input, "GET / HTTP/1.1\r\nHost: "+address+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(output), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
	_ = input.Close()
	if waitErr := stream.Wait(); waitErr != nil || err != nil || string(body) != "through-ssh" {
		t.Fatalf("SSH stream: body=%q read=%v wait=%v", body, err, waitErr)
	}
}
