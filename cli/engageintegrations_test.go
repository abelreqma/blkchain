package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/tooldef"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// engageintegrations_test.go pins which executor registry gets which operator
// instrument.
//
// Every MCP session here is an in-process server on a loopback httptest
// listener, and the out-of-band client is the stand-in shell script
// fakeOOBClient writes. No test here reaches a target host, and none drives the
// operator's own Burp.

// engageMCPFixtureTools stands in for Burp's tool set with one tool of each
// class the classifier assigns: a request tool, a read tool, a pure tool and a
// denied instrument-state tool.
var engageMCPFixtureTools = []string{
	"send_http1_request",
	"get_proxy_http_history",
	"base64_encode",
	"set_proxy_intercept_state",
}

// engageMCPFixtureRegistered is what a gated task registers from that set. The
// instrument-state tool is absent because the classifier denies it.
var engageMCPFixtureRegistered = []string{
	"mcp__burp__base64_encode",
	"mcp__burp__get_proxy_http_history",
	"mcp__burp__send_http1_request",
}

// engageOOBRegistered is the out-of-band pair, sorted.
var engageOOBRegistered = []string{"oob_interactions", "oob_payload"}

// engageMCPWriteConfig writes one MCP client config naming server and points
// chatMCPConfigEnv at it.
func engageMCPWriteConfig(t *testing.T, server chatMCPServer) {
	t.Helper()
	data, err := json.Marshal(chatMCPConfig{Servers: []chatMCPServer{server}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mcp-clients.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(chatMCPConfigEnv, path)
}

// engageMCPFixtureServer starts an MCP server offering tools over a loopback
// HTTP listener and allowlists exactly what it offers.
func engageMCPFixtureServer(t *testing.T, server string, tools []string) {
	t.Helper()
	engageMCPFixtureServerAllowing(t, server, tools, tools)
}

// engageMCPFixtureServerAllowing starts an MCP server offering offered over a
// loopback HTTP listener and allowlists allowed, which lets a test configure an
// allowlist the server does not satisfy.
func engageMCPFixtureServerAllowing(t *testing.T, server string, offered, allowed []string) {
	t.Helper()
	fixture := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	type input struct {
		Message string `json:"message"`
	}
	for _, name := range offered {
		mcp.AddTool(fixture, &mcp.Tool{Name: name, Description: "fixture tool"},
			func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, any, error) {
				return nil, map[string]any{"echo": in.Message}, nil
			})
	}
	endpoint := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return fixture },
		&mcp.StreamableHTTPOptions{JSONResponse: true}))
	t.Cleanup(endpoint.Close)
	engageMCPWriteConfig(t, chatMCPServer{
		Name: server, Transport: "http", URL: endpoint.URL, AllowTools: allowed,
	})
}

// engageMCPClosedServer points the MCP client config at a loopback URL on port
// 0, which is how a configured Burp looks while Burp is closed. Port 0 can hold
// no listener, so the dial fails inside the kernel: nothing is listening, and no
// port has to stay free for that to hold.
func engageMCPClosedServer(t *testing.T, server string, tools []string) {
	t.Helper()
	engageMCPWriteConfig(t, chatMCPServer{
		Name: server, Transport: "http", URL: "http://127.0.0.1:0", AllowTools: tools,
	})
}

// engageNoMCPConfig points the MCP client config at an absent file, which is how
// an operator with no outbound MCP server configured looks.
func engageNoMCPConfig(t *testing.T) {
	t.Helper()
	t.Setenv(chatMCPConfigEnv, filepath.Join(t.TempDir(), "absent.json"))
}

// engageIntegrationDeps builds the deps a gated executor holds: a real gate over
// 10.0.0.0/24 and the per-episode captured-output store.
func engageIntegrationDeps(t *testing.T) engageDeps {
	t.Helper()
	d := testDeps(t, nil)
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	return d
}

// engageIntegrationNames registers the integrations into a fresh registry and
// returns the sorted names they added. The registry holds nothing else, so the
// result is an exact set.
func engageIntegrationNames(t *testing.T, d engageDeps, task engagement.Task) []string {
	t.Helper()
	reg := tooldef.NewRegistry()
	closeIntegrations, err := registerEngageIntegrations(context.Background(), reg, d, task)
	if err != nil {
		t.Fatalf("registerEngageIntegrations for surface %q: %v", task.Surface, err)
	}
	t.Cleanup(closeIntegrations)
	names := reg.Names()
	sort.Strings(names)
	return names
}

func TestEngageIntegrationsGiveBurpToolsToAWebTaskOnly(t *testing.T) {
	engageMCPFixtureServer(t, "burp", engageMCPFixtureTools)
	d := engageIntegrationDeps(t)

	web := engageIntegrationNames(t, d, engagement.Task{ID: "t-web", Surface: engagement.SurfaceWeb, Target: "10.0.0.5"})
	if !reflect.DeepEqual(web, engageMCPFixtureRegistered) {
		t.Errorf("web surface registered %v, want %v", web, engageMCPFixtureRegistered)
	}

	cloud := engageIntegrationNames(t, d, engagement.Task{ID: "t-cloud", Surface: engagement.SurfaceCloud, Target: "10.0.0.5"})
	if len(cloud) != 0 {
		t.Errorf("cloud surface registered %v, want none of the web instrument's tools", cloud)
	}
}

func TestEngageIntegrationsGiveOOBToolsToEverySurface(t *testing.T) {
	engageNoMCPConfig(t)
	t.Setenv(oobServerEnv, "oast.fixture.test")
	fakeOOBClient(t, oobFakeRecord)
	d := engageIntegrationDeps(t)
	for _, surface := range []engagement.Surface{
		engagement.SurfaceWeb,
		engagement.SurfaceNetwork,
		engagement.SurfaceCloud,
		engagement.SurfaceContainer,
		engagement.SurfaceAD,
		engagement.SurfaceAISecurity,
	} {
		got := engageIntegrationNames(t, d, engagement.Task{ID: "t-" + string(surface), Surface: surface, Target: "10.0.0.5"})
		if !reflect.DeepEqual(got, engageOOBRegistered) {
			t.Errorf("surface %q registered %v, want %v", surface, got, engageOOBRegistered)
		}
	}
}

// TestEngageIntegrationsRegisterNoRequestToolWithoutAGate pins the decision for
// the ungated executor path: the whole set is withheld, not just the request
// tool. The gated case is asserted first so the two ungated cases cannot pass by
// the helper registering nothing at all.
func TestEngageIntegrationsRegisterNoRequestToolWithoutAGate(t *testing.T) {
	engageMCPFixtureServer(t, "burp", engageMCPFixtureTools)
	t.Setenv(oobServerEnv, "oast.fixture.test")
	fakeOOBClient(t, oobFakeRecord)
	task := engagement.Task{ID: "t-web", Surface: engagement.SurfaceWeb, Target: "10.0.0.5"}

	gated := engageIntegrationDeps(t)
	want := append(append([]string{}, engageMCPFixtureRegistered...), engageOOBRegistered...)
	sort.Strings(want)
	if got := engageIntegrationNames(t, gated, task); !reflect.DeepEqual(got, want) {
		t.Fatalf("the gated control registered %v, want %v", got, want)
	}

	noGate := engageIntegrationDeps(t)
	noGate.Gate = nil
	if got := engageIntegrationNames(t, noGate, task); len(got) != 0 {
		t.Errorf("a task with no gate registered %v, want nothing", got)
	}

	noRuns := engageIntegrationDeps(t)
	noRuns.Runs = nil
	if got := engageIntegrationNames(t, noRuns, task); len(got) != 0 {
		t.Errorf("a task with no captured-output store registered %v, want nothing", got)
	}
}

// TestEngageIntegrationsDegradeWhenAnMCPServerCannotBeOpened pins the
// unattended handling: the task keeps its own tools and runs on, it gains no
// mcp__ tool, and the degradation is in the audit record. The chat path's fatal
// handling is unchanged, which is the difference between an attended turn and a
// task.
//
// The two cases fail at different points of the session walk. A server that
// cannot be reached fails before any tool is built. A server that does not offer
// an allowlisted tool fails in the check that runs after its tool loop, once the
// tools it did offer have already reached the sink, so it is the case that shows
// those tools were not registered. mcp-clients.example.json's own note makes the
// second the expected one: the allowlist has to match the Burp version.
func TestEngageIntegrationsDegradeWhenAnMCPServerCannotBeOpened(t *testing.T) {
	t.Run("the server cannot be reached", func(t *testing.T) {
		engageMCPClosedServer(t, engageMCPWebInstrument, engageMCPFixtureTools)
		assertEngageMCPDegradesWithNoToolRegistered(t)
	})
	t.Run("the server does not offer an allowlisted tool", func(t *testing.T) {
		absent := append(append([]string{}, engageMCPFixtureTools...), "send_http2_request")
		engageMCPFixtureServerAllowing(t, engageMCPWebInstrument, engageMCPFixtureTools, absent)
		assertEngageMCPDegradesWithNoToolRegistered(t)
	})
}

// assertEngageMCPDegradesWithNoToolRegistered registers the integrations over
// whatever MCP client config the caller set up and asserts the three parts of
// the degrade: no error, nothing in the registry but the executor's own tool,
// and the audit record.
func assertEngageMCPDegradesWithNoToolRegistered(t *testing.T) {
	t.Helper()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	ctx = withEngageTelemetry(ctx, newEngageTelemetry(ws, cancel))

	reg := tooldef.NewRegistry()
	if err := reg.Register(&recordingMCPTool{name: "run_command"}); err != nil {
		t.Fatal(err)
	}
	closeIntegrations, err := registerEngageIntegrations(ctx, reg, engageIntegrationDeps(t),
		engagement.Task{ID: "t-web", Surface: engagement.SurfaceWeb, Target: "10.0.0.5"})
	if err != nil {
		t.Fatalf("a server that cannot be opened took the task down: %v", err)
	}
	defer closeIntegrations()
	if got := reg.Names(); !reflect.DeepEqual(got, []string{"run_command"}) {
		t.Errorf("registry = %v, want the executor's own tool and no mcp__ tool", got)
	}
	if ctx.Err() != nil {
		t.Fatalf("the episode was stopped: %v", context.Cause(ctx))
	}
	data, err := os.ReadFile(filepath.Join(ws.Dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(data), engageMCPUnavailableAction) {
		t.Fatalf("audit err=%v data=%q, want a %s record", err, data, engageMCPUnavailableAction)
	}
}

func TestEngageIntegrationsRegisterNothingWithNoConfiguredServer(t *testing.T) {
	engageNoMCPConfig(t)
	d := engageIntegrationDeps(t)
	reg := tooldef.NewRegistry()
	closeIntegrations, err := registerEngageIntegrations(context.Background(),
		reg, d, engagement.Task{ID: "t-web", Surface: engagement.SurfaceWeb, Target: "10.0.0.5"})
	if err != nil {
		t.Fatalf("an absent MCP client config returned an error: %v", err)
	}
	defer closeIntegrations()
	for _, name := range reg.Names() {
		if strings.HasPrefix(name, "mcp__") {
			t.Errorf("%s registered with no configured MCP server", name)
		}
	}
	if got := reg.Names(); len(got) != 0 {
		t.Errorf("registered %v with no configured server and no configured interactsh server, want nothing", got)
	}
}

// TestEngageIntegrationsOOBTakesNoScopeCheck pins that the interactsh server is
// operator infrastructure rather than an engagement target: it is outside the
// gate's scope and the tools register anyway.
func TestEngageIntegrationsOOBTakesNoScopeCheck(t *testing.T) {
	engageNoMCPConfig(t)
	const oobHost = "oast.fixture.test"
	t.Setenv(oobServerEnv, oobHost)
	fakeOOBClient(t, oobFakeRecord)
	d := engageIntegrationDeps(t)
	if d.Gate.Scope.InScope(oobHost) {
		t.Fatalf("%s is inside the test gate's scope, so this test cannot show that no scope check is applied", oobHost)
	}
	reg := tooldef.NewRegistry()
	closeIntegrations, err := registerEngageIntegrations(context.Background(),
		reg, d, engagement.Task{ID: "t-cloud", Surface: engagement.SurfaceCloud, Target: "10.0.0.5"})
	if err != nil {
		t.Fatalf("registerEngageIntegrations: %v", err)
	}
	defer closeIntegrations()
	names := reg.Names()
	sort.Strings(names)
	if !reflect.DeepEqual(names, engageOOBRegistered) {
		t.Fatalf("registered %v for a task whose scope holds no interactsh host, want %v", names, engageOOBRegistered)
	}
	if _, ok := reg.Get("oob_payload"); !ok {
		t.Error("oob_payload is not reachable")
	}
}
