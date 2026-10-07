package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
)

// engagerunner_env_test.go pins the declared-environment contract between the two
// halves of the runner. workerArgs forwards the operator's declared names into the
// worker container; the launcher replaces the environment of every command it
// starts, so the names have to reach the launcher's request as well or a carrier
// never receives the value it authenticates with.

func TestFootholdEnvNamesComeFromTheDeclaration(t *testing.T) {
	r := &engageRunner{foothold: &footholdTransport{env: []string{"DEPLOY_TOKEN", "SSH_AUTH_SOCK"}}}
	if got := r.footholdEnvNames(); !reflect.DeepEqual(got, []string{"DEPLOY_TOKEN", "SSH_AUTH_SOCK"}) {
		t.Errorf("footholdEnvNames = %v", got)
	}
	if got := (&engageRunner{}).footholdEnvNames(); len(got) != 0 {
		t.Errorf("no foothold declares no names, got %v", got)
	}
	var nilRunner *engageRunner
	if got := nilRunner.footholdEnvNames(); len(got) != 0 {
		t.Errorf("nil runner declares no names, got %v", got)
	}
}

// The container and the launcher must be told the same names. A name forwarded
// into the worker but missing from the request is the defect this pins: the value
// exists in the container and never reaches the command.
func TestWorkerArgsAndLauncherRequestAgreeOnDeclaredNames(t *testing.T) {
	names := []string{"DEPLOY_TOKEN", "SSH_AUTH_SOCK"}
	r := &engageRunner{foothold: &footholdTransport{env: names}}

	args := engageWorkerArgs("blk-worker-test", "guard", "image", "", r.footholdEnvNames())
	forwarded := map[string]bool{}
	for i, a := range args {
		if a == "--env" && i+1 < len(args) && !strings.Contains(args[i+1], "=") {
			forwarded[args[i+1]] = true
		}
	}

	data, err := launcherRequest([]pipelineStage{{Binary: "id"}}, 1024, 30*time.Second, r.footholdEnvNames())
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Env []string `json:"env"`
	}
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}

	for _, name := range names {
		if !forwarded[name] {
			t.Errorf("%s is not forwarded into the worker container", name)
		}
	}
	if !reflect.DeepEqual(request.Env, names) {
		t.Errorf("launcher request env = %v, want %v", request.Env, names)
	}
}

// Nothing but the declared names crosses, so a worker with no foothold carries no
// name-only --env argument at all.
func TestWorkerWithoutFootholdForwardsNoNames(t *testing.T) {
	args := engageWorkerArgs("blk-worker-test", "guard", "image", "", (&engageRunner{}).footholdEnvNames())
	for i, a := range args {
		if a == "--env" && i+1 < len(args) && !strings.Contains(args[i+1], "=") {
			t.Errorf("unexpected forwarded name %q", args[i+1])
		}
	}
}

// A declared name reaches the gate's foothold declaration and the runner alike, so
// the parsed RoE is the single source for both.
func TestDeclaredEnvNamesSurviveFootholdParsing(t *testing.T) {
	f, err := secgate.ParseFoothold("10.0.0.9 transport=command exec=kubectl exec -i web-0 --")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Env) != 0 {
		t.Fatalf("no env= declared, got %v", f.Env)
	}
	f, err = secgate.ParseFoothold("10.0.0.9 transport=command env=DEPLOY_TOKEN,SSH_AUTH_SOCK exec=kubectl exec -i web-0 --")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.Env, []string{"DEPLOY_TOKEN", "SSH_AUTH_SOCK"}) {
		t.Errorf("parsed env = %v", f.Env)
	}
}
