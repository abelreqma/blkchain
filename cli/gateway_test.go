package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertEnvLines_ReplaceInPlace(t *testing.T) {
	existing := []byte(strings.Join([]string{
		"# header comment",
		"FOO=1",
		"API_SERVER_KEY=old-secret",
		"BAR=2",
	}, "\n") + "\n")

	out := string(upsertEnvLines(existing, []envKV{
		{key: "API_SERVER_ENABLED", val: "true"},
		{key: "API_SERVER_KEY", val: "new-secret", secret: true},
	}))

	// Replaced in place, order preserved, unrelated lines untouched.
	wantSubstr := "# header comment\nFOO=1\nAPI_SERVER_KEY=new-secret\nBAR=2\n"
	if !strings.Contains(out, wantSubstr) {
		t.Errorf("in-place replace/order not preserved:\n%s", out)
	}
	if strings.Contains(out, "old-secret") {
		t.Errorf("old value survived:\n%s", out)
	}
	// The missing key was appended exactly once.
	if strings.Count(out, "API_SERVER_ENABLED=true") != 1 {
		t.Errorf("API_SERVER_ENABLED not appended exactly once:\n%s", out)
	}
	if strings.Count(out, "API_SERVER_KEY=") != 1 {
		t.Errorf("API_SERVER_KEY duplicated:\n%s", out)
	}
}

func TestUpsertEnvLines_AppendMissing(t *testing.T) {
	out := string(upsertEnvLines([]byte("EXISTING=x\n"), []envKV{
		{key: "API_SERVER_ENABLED", val: "true"},
		{key: "API_SERVER_KEY", val: "s", secret: true},
	}))
	for _, want := range []string{"EXISTING=x", "API_SERVER_ENABLED=true", "API_SERVER_KEY=s"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output should end with a newline:\n%q", out)
	}
}

func TestWriteEnvFile_ModeAndNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")

	changed, err := writeEnvFile(p, []envKV{
		{key: "API_SERVER_ENABLED", val: "true"},
		{key: "API_SERVER_KEY", val: "top-secret", secret: true},
	})
	if err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}
	if !changed {
		t.Errorf("first write should report changed=true")
	}

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}

	// No temp file left behind by the atomic rename.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestWriteEnvFile_Idempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	updates := []envKV{
		{key: "API_SERVER_ENABLED", val: "true"},
		{key: "API_SERVER_KEY", val: "s", secret: true},
	}
	if _, err := writeEnvFile(p, updates); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first, _ := os.ReadFile(p)

	changed, err := writeEnvFile(p, updates)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if changed {
		t.Errorf("second identical write should report changed=false")
	}
	second, _ := os.ReadFile(p)
	if string(first) != string(second) {
		t.Errorf("content not stable across identical writes:\n%s\n---\n%s", first, second)
	}
	// No backup written when nothing changed.
	if _, err := os.Stat(p + gatewayBackupSuffix); err == nil {
		t.Errorf("backup should not exist for an unchanged write")
	}
}

func TestWriteEnvFile_BackupOnChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("API_SERVER_KEY=old\nKEEP=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeEnvFile(p, []envKV{{key: "API_SERVER_KEY", val: "new", secret: true}}); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}
	bak, err := os.ReadFile(p + gatewayBackupSuffix)
	if err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	if !strings.Contains(string(bak), "API_SERVER_KEY=old") {
		t.Errorf("backup missing old content:\n%s", bak)
	}
}

func TestResolveGatewaySecret_EnvBeatsFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("OMLX_API=fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OMLX_API", "fromenv")
	t.Setenv("OMLX_API_KEY", "")

	val, src, err := resolveGatewaySecret(root)
	if err != nil {
		t.Fatalf("resolveGatewaySecret: %v", err)
	}
	if val != "fromenv" || src != "OMLX_API" {
		t.Errorf("got (%q, %q), want (fromenv, OMLX_API)", val, src)
	}
}

// The project .env reaches the gateway through the environment blk loads it
// into at startup.
func TestResolveGatewaySecret_ProjectEnvFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("OMLX_API_KEY=filekey\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OMLX_API", "")
	t.Setenv("OMLX_API_KEY", "")
	applyEnvFile(root)

	val, src, err := resolveGatewaySecret(root)
	if err != nil {
		t.Fatalf("resolveGatewaySecret: %v", err)
	}
	if val != "filekey" || src != "OMLX_API_KEY" {
		t.Errorf("got (%q, %q), want (filekey, OMLX_API_KEY)", val, src)
	}
}

func TestResolveGatewaySecret_MissingNeverLeaks(t *testing.T) {
	root := t.TempDir() // no .env
	t.Setenv("OMLX_API", "")
	t.Setenv("OMLX_API_KEY", "")

	_, _, err := resolveGatewaySecret(root)
	if err == nil {
		t.Fatalf("expected an error when no secret is set")
	}
	if !strings.Contains(err.Error(), "OMLX_API") {
		t.Errorf("error should name the env var to set, got: %v", err)
	}
}

func TestSummarizeUpdates_RedactsSecret(t *testing.T) {
	lines := summarizeUpdates([]envKV{
		{key: "API_SERVER_ENABLED", val: "true"},
		{key: "API_SERVER_KEY", val: "super-secret-value", secret: true},
	})
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "super-secret-value") {
		t.Errorf("secret value leaked into summary:\n%s", joined)
	}
	if !strings.Contains(joined, "API_SERVER_ENABLED=true") {
		t.Errorf("non-secret value should be shown:\n%s", joined)
	}
	if !strings.Contains(joined, "API_SERVER_KEY") {
		t.Errorf("secret key name should be shown:\n%s", joined)
	}
}

func TestRunGatewaySetsUnbuffered(t *testing.T) {
	fakeRoot(t)
	t.Setenv("HERMES_HOME", t.TempDir())
	t.Setenv("OMLX_API", "test-only-value")
	fakeBinOnPath(t, "hermes", `echo "unbuffered=$PYTHONUNBUFFERED"`+"\n")

	var err error
	stdout := captureStdout(t, func() {
		captureStderr(t, func() { err = runGateway(nil) })
	})
	if err != nil || !strings.Contains(stdout, "unbuffered=1") {
		t.Errorf("runGateway() = %v, stdout %q, want PYTHONUNBUFFERED=1 in the child", err, stdout)
	}
}

func TestRunGatewaySanitizesChildOutput(t *testing.T) {
	fakeRoot(t)
	t.Setenv("HERMES_HOME", t.TempDir())
	t.Setenv("OMLX_API", "test-only-value")
	fakeBinOnPath(t, "hermes", evilScriptBody)

	var err error
	stdout, stderr := captureBoth(t, func() { err = runGateway(nil) })
	if err != nil {
		t.Fatalf("runGateway() error = %v", err)
	}
	assertClean(t, "stdout", stdout, "out-visible-tail")
	assertClean(t, "stderr", stderr, "err-visible-tail")
}
