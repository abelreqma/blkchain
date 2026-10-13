package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/tooldef"
)

// oobFakeArgvParse is the stand-in client's argv parse. It reads the paths out
// of the argv blk builds, so a test fails if an element moves or is folded into
// another.
const oobFakeArgvParse = `#!/bin/sh
payload_file=""; out_file=""; servers=""; count=1; token=""
while [ $# -gt 0 ]; do
	case "$1" in
	-psf) payload_file="$2"; shift 2 ;;
	-o) out_file="$2"; shift 2 ;;
	-server) servers="$2"; shift 2 ;;
	-n) count="$2"; shift 2 ;;
	-token) token="$2"; shift 2 ;;
	*) shift ;;
	esac
done
id="p$$"
payload="$id.oast.fixture.test"
`

// fakeOOBClient writes a stand-in interactsh-client and points
// BLKCHAIN_OOB_CLIENT at it, so the suite reaches no interactsh server. body is
// shell run after the argv parse, with $payload_file, $out_file, $servers,
// $count, $token, $id and $payload set.
func fakeOOBClient(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "interactsh-client")
	if err := os.WriteFile(path, []byte(oobFakeArgvParse+body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_OOB_CLIENT", path)
}

// oobFakeRecord emits one interaction record, then the payload. The payload is
// written last because blk waits on the payload file, so everything this client
// reports is on disk by the time a payload is returned.
const oobFakeRecord = `
printf '{"protocol":"dns","unique-id":"%s","full-id":"%s","remote-address":"198.51.100.7","timestamp":"2026-10-13T12:00:00Z"}\n' "$id" "$id" > "$out_file"
printf '{"protocol":"http","unique-id":"%s","full-id":"%s","remote-address":"198.51.100.9","timestamp":"2026-10-13T12:00:05Z"}\n' "$id" "$id" >> "$out_file"
printf '%s\n' "$payload" > "$payload_file"
exec sleep 60
`

// oobTargetRegistry builds the registry a target turn gets, with no MCP client
// config so the turn stays hermetic.
func oobTargetRegistry(t *testing.T) (*tooldef.Registry, func()) {
	t.Helper()
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	registry, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil,
		"Assess 192.0.2.5", nil, AnswerOpts{requiredAction: "target action"})
	if err != nil {
		t.Fatal(err)
	}
	return registry, closeTools
}

func oobCall(t *testing.T, registry *tooldef.Registry, name, args string) string {
	t.Helper()
	tool, ok := registry.Get(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	out, err := tool.Call(context.Background(), args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return out
}

func TestOOBToolsAreAbsentWithoutAConfiguredServer(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "")
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	for _, name := range []string{"oob_payload", "oob_interactions"} {
		if _, ok := registry.Get(name); ok {
			t.Errorf("%s was offered with no configured interactsh server", name)
		}
	}
}

func TestOOBToolsArePresentWithAConfiguredServer(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test")
	fakeOOBClient(t, oobFakeRecord)
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	for _, name := range []string{"oob_payload", "oob_interactions"} {
		if _, ok := registry.Get(name); !ok {
			t.Errorf("%s was not offered with a configured interactsh server", name)
		}
	}
	if _, ok := registry.Get("oob_payload"); ok {
		if out := oobCall(t, registry, "oob_interactions", `{}`); !strings.Contains(out, "call oob_payload first") {
			t.Errorf("interactions before a payload = %q", out)
		}
	}
}

// TestOOBPayloadDoesNotOrphanTheFirstPayload pins the idempotence that matters:
// the stand-in client names its payload after its own pid and truncates the
// payload file, so a second client would replace the payload the first one
// registered and the second call would return a different domain.
func TestOOBPayloadDoesNotOrphanTheFirstPayload(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test")
	fakeOOBClient(t, oobFakeRecord)
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	first := oobCall(t, registry, "oob_payload", `{}`)
	second := oobCall(t, registry, "oob_payload", `{"count":2}`)
	if !strings.Contains(first, ".oast.fixture.test") {
		t.Fatalf("no payload domain was returned: %q", first)
	}
	if first != second {
		t.Fatalf("a second payload request orphaned the first: %q then %q", first, second)
	}
}

// TestOOBPayloadReportsAClientThatCannotRegister covers the failure the
// operator will actually hit: a server that does not answer. The client exits
// without writing a payload, and a second call must repeat the reason instead
// of reporting an empty success.
func TestOOBPayloadReportsAClientThatCannotRegister(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test")
	fakeOOBClient(t, "\nprintf 'could not register to %s\\n' \"$servers\" >&2\nexit 1\n")
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	for _, out := range []string{oobCall(t, registry, "oob_payload", `{}`), oobCall(t, registry, "oob_payload", `{}`)} {
		if !strings.HasPrefix(out, "oob_payload: interactsh-client") {
			t.Fatalf("a client that cannot register was not reported: %q", out)
		}
		if !strings.Contains(out, "could not register to oast.fixture.test") {
			t.Fatalf("the client's own reason was dropped: %q", out)
		}
	}
}

func TestOOBInteractionsReportTypeTimestampAndRemoteAddress(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test")
	fakeOOBClient(t, oobFakeRecord)
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	payload := strings.TrimSpace(strings.TrimPrefix(oobCall(t, registry, "oob_payload", `{}`), "out-of-band payload domains:"))
	out := oobCall(t, registry, "oob_interactions", `{"payload":"`+payload+`"}`)
	// The client reports the correlation id, the label the payload domain
	// starts with, as the interaction's full id.
	id, _, _ := strings.Cut(payload, ".")
	for _, want := range []string{"2 out-of-band interactions", "DNS", "HTTP", "2026-10-13T12:00:00Z", "198.51.100.7", "198.51.100.9", id} {
		if !strings.Contains(out, want) {
			t.Errorf("interactions missing %q: %q", want, out)
		}
	}
	if !strings.Contains(out, "UNTRUSTED oob BEGIN") || !strings.Contains(out, "UNTRUSTED oob END") {
		t.Errorf("interaction data was not wrapped as untrusted: %q", out)
	}
	if other := oobCall(t, registry, "oob_interactions", `{"payload":"unrelated.oast.fixture.test"}`); !strings.Contains(other, "0 out-of-band interactions") {
		t.Errorf("another payload's filter returned records: %q", other)
	}
}

// oobFakeFlood emits more records than either cap allows, with a sentinel
// record last. The sentinel sits past the byte cap, so it proves the file read
// is bounded and not only the count.
const oobFakeFlood = `
pad=$(printf '%2000s' '' | tr ' ' x)
i=1
while [ "$i" -le 150 ]; do
	printf '{"protocol":"dns","unique-id":"%s","full-id":"%s","remote-address":"198.51.100.1","timestamp":"2026-10-13T12:00:00Z","pad":"%s"}\n' "$id" "$id" "$pad" >> "$out_file"
	i=$((i+1))
done
printf '{"protocol":"dns","unique-id":"%s","full-id":"%s","remote-address":"203.0.113.254","timestamp":"2026-10-13T12:00:00Z"}\n' "$id" "$id" >> "$out_file"
printf '%s\n' "$payload" > "$payload_file"
exec sleep 60
`

func TestOOBInteractionsHoldTheCountAndByteCaps(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test")
	fakeOOBClient(t, oobFakeFlood)
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	oobCall(t, registry, "oob_payload", `{}`)
	out := oobCall(t, registry, "oob_interactions", `{}`)
	if !strings.HasPrefix(out, "50 out-of-band interactions, older ones not shown") {
		t.Fatalf("the count cap did not hold: %q", firstLine(out))
	}
	if strings.Contains(out, "203.0.113.254") {
		t.Fatal("a record past the byte cap was read")
	}
	if strings.Count(out, "198.51.100.1") != oobMaxInteractions {
		t.Fatalf("reported %d records, want %d", strings.Count(out, "198.51.100.1"), oobMaxInteractions)
	}
	if limited := oobCall(t, registry, "oob_interactions", `{"limit":3}`); strings.Count(limited, "198.51.100.1") != 3 {
		t.Fatalf("the requested limit did not hold: %q", firstLine(limited))
	}
}

// TestOOBLiveLoopbackInteraction runs the real interactsh-client against a
// loopback interactsh server, triggers an HTTP callback to the payload domain,
// and requires the interaction to come back. It is gated on BLKCHAIN_OOB_LIVE
// and refuses a server that is not on loopback, so no interaction data can
// leave this machine.
func TestOOBLiveLoopbackInteraction(t *testing.T) {
	if os.Getenv("BLKCHAIN_OOB_LIVE") != "1" {
		t.Skip("set BLKCHAIN_OOB_LIVE=1 with a loopback interactsh server to run this")
	}
	servers, err := oobServers()
	if err != nil || len(servers) != 1 {
		t.Fatalf("BLKCHAIN_OOB_SERVER must name one loopback server: %v %v", servers, err)
	}
	host, _, _ := strings.Cut(servers[0], ":")
	if host != "127.0.0.1" && host != "localhost" {
		t.Fatalf("%q is not a loopback interactsh server", servers[0])
	}
	registry, closeTools := oobTargetRegistry(t)
	defer closeTools()
	out := oobCall(t, registry, "oob_payload", `{}`)
	fields := strings.Fields(out)
	payload := fields[len(fields)-1]
	if !strings.HasSuffix(payload, "."+servers[0]) {
		t.Fatalf("oob_payload returned no payload for the configured server: %q", out)
	}
	t.Logf("payload: %s", payload)
	request, err := http.NewRequest(http.MethodGet, "http://"+servers[0]+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = payload
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	deadline := time.Now().Add(45 * time.Second)
	for {
		seen := oobCall(t, registry, "oob_interactions", `{"payload":"`+payload+`"}`)
		if strings.Contains(seen, "HTTP ") {
			t.Logf("interactions:\n%s", seen)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no HTTP interaction was reported: %q", seen)
		}
		time.Sleep(time.Second)
	}
}

func TestOOBServerValueMustBeAHostnameList(t *testing.T) {
	for _, value := range []string{
		"-token", "oast.fixture.test;id", "oast fixture test", "http://oast.fixture.test",
		"oast.fixture.test/path", "oast.fixture.test:99999x", "a.test,b.test,c.test,d.test,e.test",
	} {
		t.Setenv("BLKCHAIN_OOB_SERVER", value)
		if _, err := oobServers(); err == nil {
			t.Errorf("%q was accepted as an interactsh server list", value)
		}
		t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
		if _, _, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil,
			"Assess 192.0.2.5", nil, AnswerOpts{requiredAction: "target action"}); err == nil {
			t.Errorf("a turn started with %q configured as the interactsh server", value)
		}
	}
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test:8443, 127.0.0.1:8080")
	servers, err := oobServers()
	if err != nil || len(servers) != 2 || servers[1] != "127.0.0.1:8080" {
		t.Fatalf("a valid host:port list was rejected: %v %v", servers, err)
	}
}

func TestOOBMissingClientBinaryIsNamed(t *testing.T) {
	t.Setenv("BLKCHAIN_OOB_SERVER", "oast.fixture.test")
	t.Setenv("BLKCHAIN_OOB_CLIENT", "")
	t.Setenv("PATH", t.TempDir())
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	_, _, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil,
		"Assess 192.0.2.5", nil, AnswerOpts{requiredAction: "target action"})
	if err == nil || !strings.Contains(err.Error(), "interactsh-client is not on PATH") {
		t.Fatalf("a missing client binary was not named: %v", err)
	}
	t.Setenv("BLKCHAIN_OOB_CLIENT", "interactsh-client")
	if _, err := oobClientPath(); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("a relative client path was accepted: %v", err)
	}
}
