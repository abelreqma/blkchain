package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
)

func writeKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, []byte("PRIVATE-KEY-BYTES\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseFootholdOrFail(t *testing.T, entry string) *secgate.Foothold {
	t.Helper()
	f, err := secgate.ParseFoothold(entry)
	if err != nil {
		t.Fatalf("ParseFoothold(%q): %v", entry, err)
	}
	return f
}

// TestShellQuoteArgvSurvivesARemoteShell is the security property of the ssh
// carrier: the remote side always parses a shell, so an argument containing a
// space, a quote, or a metacharacter must still arrive as exactly one argument.
// The expectation is checked against a real shell rather than a hand-written
// string, so it cannot encode the same mistake as the implementation.
func TestShellQuoteArgvSurvivesARemoteShell(t *testing.T) {
	cases := [][]string{
		{"id"},
		{"find", "/", "-perm", "-4000", "-type", "f"},
		{"grep", "a b c"},
		{"echo", "it's"},
		{"echo", `"quoted"`},
		{"echo", "a;rm -rf /"},
		{"echo", "$(whoami)"},
		{"echo", "`whoami`"},
		{"echo", "a|b", "c&d", "e>f", "g<h"},
		{"echo", "tab\there"},
		{"echo", "new\nline"},
		{"echo", "*"},
		{"echo", ""},
		{"echo", `back\slash`},
		{"echo", "'", `'\''`},
	}
	for _, argv := range cases {
		quoted := shellQuoteArgv(argv)
		// printf %s\0 per argument lets the test read back the exact argument
		// boundaries a shell produced, including empty arguments.
		out, err := exec.Command("/bin/sh", "-c", `printf '%s\0' `+quoted).Output()
		if err != nil {
			t.Fatalf("shell rejected %q (from %v): %v", quoted, argv, err)
		}
		fields := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		if len(fields) != len(argv) {
			t.Fatalf("argv %v quoted as %q split into %d arguments %q, want %d", argv, quoted, len(fields), fields, len(argv))
		}
		for i := range argv {
			if fields[i] != argv[i] {
				t.Errorf("argv %v: argument %d = %q, want %q", argv, i, fields[i], argv[i])
			}
		}
	}
}

func TestFootholdSSHTransport(t *testing.T) {
	key := writeKeyFile(t)
	t.Setenv("BLK_TEST_FOOTHOLD_KEY", key)
	f := parseFootholdOrFail(t, "10.10.5.21 transport=ssh user=svc port=2222 key=$BLK_TEST_FOOTHOLD_KEY")
	tr, err := newFootholdTransport(f)
	if err != nil {
		t.Fatalf("newFootholdTransport: %v", err)
	}
	argv := tr.Wrap([]string{"find", "/", "-perm", "-4000"})
	joined := strings.Join(argv, " ")
	if argv[0] != "ssh" {
		t.Fatalf("carrier argv[0] = %q, want ssh", argv[0])
	}
	for _, want := range []string{
		"-i " + footholdSecretDir + "/key",
		"BatchMode=yes",
		"PasswordAuthentication=no",
		"IdentitiesOnly=yes",
		"LogLevel=ERROR",
		"-p 2222",
		"svc@10.10.5.21",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("carrier argv %q is missing %q", joined, want)
		}
	}
	// The command reaches the remote shell as one quoted argument, so the remote
	// argv equals the authorized argv.
	if last := argv[len(argv)-1]; last != `'find' '/' '-perm' '-4000'` {
		t.Errorf("remote command = %q, want the shell-quoted argv", last)
	}
	if got := tr.secrets[footholdSecretDir+"/key"]; string(got) != "PRIVATE-KEY-BYTES\n" {
		t.Errorf("key secret = %q, want the key file content", got)
	}
	if len(tr.secretPaths()) != 1 {
		t.Errorf("secretPaths() = %v, want only the key", tr.secretPaths())
	}
}

// TestFootholdSSHPinsHostKeyWhenDeclared pins that declaring knownhosts turns on
// strict host-key checking, so the pivot's own connection cannot be
// man-in-the-middled by the target network, and that omitting it does not.
func TestFootholdSSHPinsHostKeyWhenDeclared(t *testing.T) {
	key := writeKeyFile(t)
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte("10.10.5.21 ssh-ed25519 AAAA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pinned, err := newFootholdTransport(parseFootholdOrFail(t, "10.10.5.21 user=svc key="+key+" knownhosts="+known))
	if err != nil {
		t.Fatalf("newFootholdTransport: %v", err)
	}
	joined := strings.Join(pinned.Wrap([]string{"id"}), " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=yes") || !strings.Contains(joined, "UserKnownHostsFile="+footholdSecretDir+"/known_hosts") {
		t.Errorf("pinned carrier = %q, want strict checking against the mounted known_hosts", joined)
	}
	if _, ok := pinned.secrets[footholdSecretDir+"/known_hosts"]; !ok {
		t.Error("known_hosts was not provisioned as a secret file")
	}

	open, err := newFootholdTransport(parseFootholdOrFail(t, "10.10.5.21 user=svc key="+key))
	if err != nil {
		t.Fatalf("newFootholdTransport: %v", err)
	}
	if joined := strings.Join(open.Wrap([]string{"id"}), " "); !strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Errorf("unpinned carrier = %q, want StrictHostKeyChecking=no", joined)
	}
}

func TestFootholdCommandTransportPassesArgvThrough(t *testing.T) {
	f := parseFootholdOrFail(t, "10.10.5.21 transport=command exec=kubectl exec -i web-0 --")
	tr, err := newFootholdTransport(f)
	if err != nil {
		t.Fatalf("newFootholdTransport: %v", err)
	}
	argv := tr.Wrap([]string{"grep", "a b"})
	want := []string{"kubectl", "exec", "-i", "web-0", "--", "grep", "a b"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv carrier produced %v, want %v", argv, want)
	}
}

// TestFootholdCommandTransportQuotesWhenDeclared pins that a carrier declared as
// shell-reparsing gets quoted argv, which is what makes the registry usable for
// carriers other than kubectl-style exec.
func TestFootholdCommandTransportQuotesWhenDeclared(t *testing.T) {
	tr, err := newFootholdTransport(parseFootholdOrFail(t, "10.10.5.21 transport=command quote=shell exec=mycarrier --run"))
	if err != nil {
		t.Fatalf("newFootholdTransport: %v", err)
	}
	argv := tr.Wrap([]string{"grep", "a b"})
	if len(argv) != 3 || argv[2] != `'grep' 'a b'` {
		t.Fatalf("shell-quoting carrier produced %v", argv)
	}
}

func TestFootholdTransportFailsClosedAtSetup(t *testing.T) {
	key := writeKeyFile(t)
	t.Run("missing key file", func(t *testing.T) {
		_, err := newFootholdTransport(parseFootholdOrFail(t, "10.0.0.1 user=u key=/nonexistent/key"))
		if err == nil {
			t.Fatal("a missing key file was accepted")
		}
	})
	t.Run("unset key variable", func(t *testing.T) {
		_, err := newFootholdTransport(parseFootholdOrFail(t, "10.0.0.1 user=u key=$BLK_TEST_UNSET_KEY"))
		if err == nil || !strings.Contains(err.Error(), "not set") {
			t.Fatalf("err = %v, want an unset-variable error", err)
		}
	})
	t.Run("relative key path", func(t *testing.T) {
		_, err := newFootholdTransport(parseFootholdOrFail(t, "10.0.0.1 user=u key=relative/key"))
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("err = %v, want an absolute-path error", err)
		}
	})
	t.Run("unset declared env", func(t *testing.T) {
		_, err := newFootholdTransport(parseFootholdOrFail(t, "10.0.0.1 user=u key="+key+" env=BLK_TEST_UNSET_TOKEN"))
		if err == nil || !strings.Contains(err.Error(), "BLK_TEST_UNSET_TOKEN") {
			t.Fatalf("err = %v, want an unset-env error", err)
		}
	})
	t.Run("nil declaration", func(t *testing.T) {
		tr, err := newFootholdTransport(nil)
		if tr != nil || err != nil {
			t.Fatalf("newFootholdTransport(nil) = %v, %v, want nil, nil", tr, err)
		}
	})
}

// TestAuthorizeFootholdCarrier pins the asymmetry: the ssh carrier is built
// entirely by code so it needs no allowlist entry, which keeps ssh out of the
// model's reach, while an operator-declared command carrier must clear the same
// allowlist as any other command.
func TestAuthorizeFootholdCarrier(t *testing.T) {
	key := writeKeyFile(t)
	ssh, err := newFootholdTransport(parseFootholdOrFail(t, "10.0.0.1 user=u key="+key))
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeFootholdCarrier(&secgate.Gate{Allow: secgate.NewAllowlist()}, ssh); err != nil {
		t.Errorf("ssh carrier rejected: %v", err)
	}
	if err := authorizeFootholdCarrier(nil, nil); err != nil {
		t.Errorf("nil carrier rejected: %v", err)
	}

	cmd, err := newFootholdTransport(parseFootholdOrFail(t, "10.0.0.1 transport=command exec=kubectl exec -i p --"))
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeFootholdCarrier(&secgate.Gate{Allow: secgate.NewAllowlist("kubectl")}, cmd); err != nil {
		t.Errorf("allowlisted command carrier rejected: %v", err)
	}
	if err := authorizeFootholdCarrier(&secgate.Gate{Allow: secgate.NewAllowlist("nmap")}, cmd); err == nil {
		t.Error("an off-allowlist command carrier was accepted")
	}
	if err := authorizeFootholdCarrier(&secgate.Gate{}, cmd); err == nil {
		t.Error("a command carrier was accepted with no allowlist")
	}
}

// TestFootholdSecretWriterIsValidPython compiles the in-worker writer, so a
// syntax error cannot ship and break carrier provisioning at runtime.
func TestFootholdSecretWriterIsValidPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	cmd := exec.Command(python, "-c", "import sys; compile(sys.stdin.read(), 'writer', 'exec')")
	cmd.Stdin = strings.NewReader(footholdSecretWriter)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the secret writer does not compile: %v: %s", err, out)
	}
}

// TestFootholdSecretWriterStoresPrivateMode runs the writer the way the worker
// does and checks the result, so the 0600 mode and the parent directory are
// pinned behavior rather than an assumption about os.open flags.
func TestFootholdSecretWriterStoresPrivateMode(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	dest := filepath.Join(t.TempDir(), "nested", "key")
	cmd := exec.Command(python, "-c", footholdSecretWriter, dest)
	cmd.Stdin = strings.NewReader("SECRET")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writer failed: %v: %s", err, out)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("secret mode = %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "SECRET" {
		t.Fatalf("secret content = %q, err = %v", data, err)
	}
}

func TestFootholdPinIPs(t *testing.T) {
	hosts := []string{"10.10.5.21 jump.example.com", "10.10.5.22 other.example.com"}
	if got := footholdPinIPs(nil, hosts); got != nil {
		t.Errorf("footholdPinIPs(nil) = %v, want nil", got)
	}
	ip := footholdPinIPs(&secgate.Foothold{Host: "10.1.2.3"}, nil)
	if len(ip) != 1 || ip[0] != "10.1.2.3" {
		t.Errorf("an IP foothold pinned %v", ip)
	}
	name := footholdPinIPs(&secgate.Foothold{Host: "jump.example.com"}, hosts)
	if len(name) != 1 || name[0] != "10.10.5.21" {
		t.Errorf("a hostname foothold pinned %v, want its resolved address", name)
	}
}

// TestWorkerArgsForwardsDeclaredEnvOnly pins that only the names the operator
// declared cross into a worker, and that nothing else about the worker's
// confinement changes when a foothold is present.
func TestWorkerArgsForwardsDeclaredEnvOnly(t *testing.T) {
	image := "sha256:" + strings.Repeat("a", 64)
	with := strings.Join(engageWorkerArgs("w", "guard", image, "", []string{"FOOTHOLD_TOKEN"}), " ")
	if !strings.Contains(with, "--env FOOTHOLD_TOKEN") {
		t.Errorf("worker args %q do not forward the declared variable", with)
	}
	without := strings.Join(engageWorkerArgs("w", "guard", image, "", nil), " ")
	if strings.Contains(without, "FOOTHOLD_TOKEN") {
		t.Error("an undeclared variable reached the worker")
	}
	for _, control := range []string{"--read-only", "--cap-drop ALL", "no-new-privileges", "--user 1000:1000"} {
		if !strings.Contains(with, control) {
			t.Errorf("worker args %q lost %q when a foothold env was declared", with, control)
		}
	}
}

func TestPivotDestination(t *testing.T) {
	key := writeKeyFile(t)
	f := parseFootholdOrFail(t, "10.10.5.21 user=svc key="+key+" surfaces=local,ad")
	tr, err := newFootholdTransport(f)
	if err != nil {
		t.Fatal(err)
	}
	policy := secgate.DefaultPolicy()
	policy.Foothold = f
	g := &secgate.Gate{Policy: policy}
	withCarrier := &engageRuntime{runner: &engageRunner{foothold: tr}}

	if got := pivotDestination(g, withCarrier, secgate.SurfaceLocal); got != "10.10.5.21" {
		t.Errorf("local destination = %q, want the foothold", got)
	}
	if got := pivotDestination(g, withCarrier, secgate.SurfaceAD); got != "10.10.5.21" {
		t.Errorf("ad destination = %q, want the foothold", got)
	}
	if got := pivotDestination(g, withCarrier, secgate.SurfaceWeb); got != "" {
		t.Errorf("web destination = %q, want the sandbox", got)
	}
	// A policy that declares a foothold but a runner that holds no carrier must
	// not pivot: the destination tracks the constructed carrier, not the text.
	if got := pivotDestination(g, &engageRuntime{runner: &engageRunner{}}, secgate.SurfaceLocal); got != "" {
		t.Errorf("destination without a carrier = %q, want the sandbox", got)
	}
	if got := pivotDestination(&secgate.Gate{Policy: secgate.DefaultPolicy()}, withCarrier, secgate.SurfaceLocal); got != "" {
		t.Errorf("destination without a declaration = %q, want the sandbox", got)
	}
}

// TestLocalSurfaceCommandRunsOnTheFoothold is the whole-chain property the pivot
// exists for: a local-surface command reaches the runner wrapped in the carrier,
// a web-surface command in the same engagement does not, and the transcript
// records where each one ran.
func TestLocalSurfaceCommandRunsOnTheFoothold(t *testing.T) {
	key := writeKeyFile(t)
	roe, err := ParseRoE(strings.NewReader("## In Scope\n10.10.5.21\nlocal\n\n## Foothold\n10.10.5.21 user=svc key=" + key + "\n"))
	if err != nil {
		t.Fatalf("ParseRoE: %v", err)
	}
	if roe.Policy.Foothold == nil {
		t.Fatal("the RoE did not carry a foothold")
	}
	tr, err := newFootholdTransport(roe.Policy.Foothold)
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	trace := newActionTranscript(workspace, "off", roe.Policy.RunnerID, 10, 65536, nil)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var seen [][]pipelineStage
	runner := &engageRunner{workers: map[string]string{}, foothold: tr,
		runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
			seen = append(seen, stages)
			return runResult{Output: "ok"}, []isolatedStageResult{{Stdout: "ok"}}
		}}
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, policy: roe.Policy, cancel: func() {}})

	if res := runAuthorized(ctx, g, "id", nil, "task", 65536, time.Second, actionOrigin{TaskID: "t-local", Surface: secgate.SurfaceLocal}); res.Err != nil {
		t.Fatalf("local action failed: %v", res.Err)
	}
	if res := runAuthorized(ctx, g, "curl", []string{"http://10.10.5.21/"}, "task", 65536, time.Second, actionOrigin{TaskID: "t-web", Surface: secgate.SurfaceWeb}); res.Err != nil {
		t.Fatalf("web action failed: %v", res.Err)
	}
	if len(seen) != 2 {
		t.Fatalf("runner saw %d actions, want 2", len(seen))
	}
	if seen[0][0].Binary != "ssh" {
		t.Errorf("the local command ran as %q, want it carried by ssh", seen[0][0].Binary)
	}
	if last := seen[0][0].Args[len(seen[0][0].Args)-1]; last != "'id'" {
		t.Errorf("the carried command = %q, want the quoted authorized argv", last)
	}
	if seen[1][0].Binary != "curl" {
		t.Errorf("the web command ran as %q, want it unwrapped in the sandbox", seen[1][0].Binary)
	}

	data, err := os.ReadFile(filepath.Join(workspace, "actions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"task":"t-local"`, `"destination":"10.10.5.21"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("transcript is missing %s\n%s", want, data)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.Contains(line, `"task":"t-web"`) && strings.Contains(line, "destination") {
			t.Errorf("a sandbox action recorded a foothold destination: %s", line)
		}
	}
}

// TestPivotedCommandRecordsTheAuthorizedCommandNotTheCarrier pins that the
// transcript and the gate both read the operator's command: the carrier is an
// execution detail, so evidence stays reviewable and a reader is not shown an
// ssh invocation in place of the command that produced the output.
func TestPivotedCommandRecordsTheAuthorizedCommandNotTheCarrier(t *testing.T) {
	key := writeKeyFile(t)
	roe, err := ParseRoE(strings.NewReader("## In Scope\n10.10.5.21\nlocal\n\n## Foothold\n10.10.5.21 user=svc key=" + key + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := newFootholdTransport(roe.Policy.Foothold)
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	trace := newActionTranscript(workspace, "off", roe.Policy.RunnerID, 10, 65536, nil)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	runner := &engageRunner{workers: map[string]string{}, foothold: tr,
		runFn: func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult) {
			return runResult{Output: "uid=0(root)"}, []isolatedStageResult{{Stdout: "uid=0(root)"}}
		}}
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, policy: roe.Policy, cancel: func() {}})
	runAuthorized(ctx, g, "sudo", []string{"-l"}, "task", 65536, time.Second, actionOrigin{TaskID: "t1", Surface: secgate.SurfaceLocal})

	data, err := os.ReadFile(filepath.Join(workspace, "actions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "sudo") {
		t.Errorf("the transcript lost the authorized command\n%s", data)
	}
	if strings.Contains(string(data), "BatchMode") {
		t.Errorf("the transcript recorded the carrier argv instead of the command\n%s", data)
	}
}

// TestPivotedRawScanUsesTheGeneralWorker pins a consequence of wrapping before
// worker selection: a raw-socket tool running on the foothold needs the
// capability there, not in the worker, so the carrier must not pull the
// privileged raw worker into an engagement that does not need it.
func TestPivotedRawScanUsesTheGeneralWorker(t *testing.T) {
	key := writeKeyFile(t)
	tr, err := newFootholdTransport(parseFootholdOrFail(t, "10.10.5.21 user=svc key="+key))
	if err != nil {
		t.Fatal(err)
	}
	direct := []pipelineStage{{Binary: "masscan", Args: []string{"-p80", "10.10.5.21", "--rate", "100"}}}
	if !pipelineNeedsRawSocket(direct) {
		t.Fatal("masscan is not recognized as needing a raw socket; the premise of this test is gone")
	}
	if pipelineNeedsRawSocket(footholdStages(tr, direct)) {
		t.Error("a carried raw scan still selects the privileged raw worker")
	}
}

func TestFootholdStagesWrapsEveryPipelineStage(t *testing.T) {
	key := writeKeyFile(t)
	tr, err := newFootholdTransport(parseFootholdOrFail(t, "10.10.5.21 user=svc key="+key))
	if err != nil {
		t.Fatal(err)
	}
	stages := []pipelineStage{
		{Binary: "cat", Args: []string{"/etc/crontab"}},
		{Binary: "grep", Args: []string{"-v", "^#"}, DiscardStderr: true},
	}
	out := footholdStages(tr, stages)
	if len(out) != 2 {
		t.Fatalf("got %d stages, want 2", len(out))
	}
	for i, s := range out {
		if s.Binary != "ssh" {
			t.Errorf("stage %d binary = %q, want ssh", i, s.Binary)
		}
	}
	if !out[1].DiscardStderr {
		t.Error("wrapping lost the stage's DiscardStderr setting")
	}
	if last := out[1].Args[len(out[1].Args)-1]; last != `'grep' '-v' '^#'` {
		t.Errorf("stage 1 carried %q", last)
	}
	// The input stages are not mutated, so a retry or an audit record built from
	// the originals still reads the authorized command.
	if stages[0].Binary != "cat" {
		t.Errorf("wrapping mutated the input stages: %+v", stages)
	}
}

// TestFootholdPromptNamesTheDestination pins that the model is told where its
// local commands go and that the runner-specific guidance is scoped, since the
// foothold has its own resolver and filesystem.
func TestFootholdPromptNamesTheDestination(t *testing.T) {
	key := writeKeyFile(t)
	roe, err := ParseRoE(strings.NewReader("## In Scope\n10.10.5.21\nlocal\n\n## Foothold\n10.10.5.21 user=svc key=" + key + " surfaces=local,ad\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Policy: roe.Policy}
	prompt := effectiveEngagePrompt(g, "base")
	for _, want := range []string{"declared a foothold", "10.10.5.21", "local, ad", "do not choose where a command runs"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt is missing %q", want)
		}
	}
	bare, err := ParseRoE(strings.NewReader("## In Scope\n10.10.5.21\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p := effectiveEngagePrompt(&secgate.Gate{Policy: bare.Policy}, "base"); strings.Contains(p, "foothold") {
		t.Errorf("an engagement with no foothold mentions one:\n%s", p)
	}
}

// TestActionScopedRunnerCarriesNoFoothold pins that the wildcard-egress
// sub-runner is built without a foothold: its accept list is deliberately narrow
// and no pivoted action uses it, so neither the foothold's address nor its
// carrier secrets belong there.
func TestActionScopedRunnerCarriesNoFoothold(t *testing.T) {
	key := writeKeyFile(t)
	roe, err := ParseRoE(strings.NewReader("## In Scope\n10.10.5.21\n*.example.test\n\n## Foothold\n10.10.5.21 user=svc key=" + key + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := newFootholdTransport(roe.Policy.Foothold)
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	trace := newActionTranscript(workspace, "off", roe.Policy.RunnerID, 10, 65536, nil)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	original := newEngageRunnerForRun
	t.Cleanup(func() { newEngageRunnerForRun = original })
	var sawFoothold *secgate.Foothold
	var built bool
	newEngageRunnerForRun = func(_ context.Context, action *RoE) (*engageRunner, error) {
		built = true
		sawFoothold = action.Policy.Foothold
		return &engageRunner{workers: map[string]string{}, remove: func(context.Context, string) error { return nil },
			runFn: func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult) {
				return runResult{Output: "scoped"}, []isolatedStageResult{{Stdout: "scoped"}}
			}}, nil
	}
	runner := &engageRunner{slots: make(chan struct{}, 1), workers: map[string]string{}, foothold: tr,
		resolve: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.6")}}, nil
		}}
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, policy: roe.Policy, cancel: func() {}})

	// A web-surface wildcard command takes the dynamic path and must not inherit
	// the foothold.
	res := runAuthorized(ctx, g, "curl", []string{"http://host.example.test/"}, "task", 65536, time.Second, actionOrigin{TaskID: "t1", Surface: secgate.SurfaceWeb})
	if !built {
		t.Fatalf("the wildcard command did not build an action-scoped runner: %+v", res)
	}
	if sawFoothold != nil {
		t.Errorf("the action-scoped runner inherited a foothold: %+v", sawFoothold)
	}
	// The parent policy is untouched, so the pivot still works for later actions.
	if roe.Policy.Foothold == nil {
		t.Error("narrowing the sub-runner's policy mutated the sealed policy")
	}
}
