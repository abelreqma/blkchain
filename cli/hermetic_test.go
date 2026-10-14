package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/histstore"
)

// hermetic_test.go keeps this package's tests off the operator's own blk state.
//
// The engage entry point opens the recall store at $XDG_DATA_HOME/blk/history.db
// and derives its default engagement workspace from $XDG_CONFIG_HOME/blkchain,
// each falling back to the home directory when the variable is unset. A test that
// reached either read whatever a real `blk engage` run had left there. A
// remembered ROE.md for this package's directory turned TestEngageAutoRequiresScope,
// which asserts the no-scope usage error, into a live engagement that wrote a
// workspace under the operator's config directory and failed two minutes later.
//
// CLAUDE.md states the default suites are hermetic, so the floor is set once for
// every test in the package rather than per test. That also covers tests added
// later, which is the part an audit of today's call sites cannot do. A test that
// wants its own directory still overrides with t.Setenv, which takes precedence
// for that test and is restored afterwards.

// testStateRoot is the per-run directory both XDG variables point inside.
var testStateRoot string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "blk-test-state-")
	if err != nil {
		panic("hermetic test state: " + err.Error())
	}
	testStateRoot = dir
	if err := os.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data")); err != nil {
		panic("hermetic test state: " + err.Error())
	}
	if err := os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config")); err != nil {
		panic("hermetic test state: " + err.Error())
	}
	// The web stack sends requests through a local intercepting proxy when one
	// is listening. An operator running Burp on the default port would otherwise
	// have every fixture request in this suite routed through it.
	if err := os.Setenv(webProxyEnv, webProxyDisabledSetting); err != nil {
		panic("hermetic test state: " + err.Error())
	}
	// An armed registry registers the out-of-band tools when an interactsh
	// server is configured, and then resolves the client binary. An operator
	// with a server of their own would otherwise attach it to every test that
	// builds one, and a client it cannot resolve fails those tests outright.
	for _, name := range []string{oobServerEnv, oobClientEnv, oobTokenEnv} {
		if err := os.Unsetenv(name); err != nil {
			panic("hermetic test state: " + err.Error())
		}
	}
	// An operator who configures a role model would otherwise have every test
	// in this suite drive that model instead of the one the test names.
	for _, name := range []string{"BLKCHAIN_ROUTER_MODEL", "BLKCHAIN_ASSESSMENT_MODEL"} {
		if err := os.Unsetenv(name); err != nil {
			panic("hermetic test state: " + err.Error())
		}
	}
	// An operator with a serve token exported would otherwise have the whole
	// suite authenticate, so a request a test builds without one would be
	// refused for a reason the test never set up.
	if err := os.Unsetenv(serveTokenEnv); err != nil {
		panic("hermetic test state: " + err.Error())
	}
	// A web-surface executor registry opens the outbound MCP servers this
	// variable names. An operator with it exported would otherwise have a test
	// that builds one connect to their real servers, start a stdio server's
	// command, and drive their own Burp.
	if err := os.Unsetenv("BLKCHAIN_MCP_CLIENT_CONFIG"); err != nil {
		panic("hermetic test state: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir) // os.Exit runs no deferred call, so clean up first.
	os.Exit(code)
}

// TestPackageStateResolvesInsideTheTestRoot is the guard on the floor above: it
// fails if TestMain stops redirecting either variable, so the suite cannot go back
// to reading the operator's store without saying so.
func TestPackageStateResolvesInsideTheTestRoot(t *testing.T) {
	if testStateRoot == "" {
		t.Fatal("TestMain did not set the hermetic state root")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	// engagementWorkspace derives from configPath, so the config assertion covers
	// the default workspace directory as well as the saved-root file.
	resolvers := map[string]func() (string, error){
		"recall store": histstore.DBPath,
		"config root":  configPath,
		"sessions dir": sessionsDir,
		"history file": historyPath,
	}
	for name, resolve := range resolvers {
		path, err := resolve()
		if err != nil {
			t.Errorf("%s did not resolve: %v", name, err)
			continue
		}
		if path == "" {
			t.Errorf("%s resolved to an empty path", name)
			continue
		}
		if !strings.HasPrefix(path, testStateRoot) {
			t.Errorf("%s resolves to %q, outside the test root %q", name, path, testStateRoot)
		}
		if strings.HasPrefix(path, filepath.Join(home, ".config")) || strings.HasPrefix(path, filepath.Join(home, ".local")) {
			t.Errorf("%s resolves into the operator's own state at %q", name, path)
		}
	}
}

// TestRecallStoreStartsEmptyInTests pins the consequence that matters: the recall
// table a test reads carries nothing from any real run, so a remembered ROE.md
// cannot decide a verdict.
func TestRecallStoreStartsEmptyInTests(t *testing.T) {
	store := histstore.OpenDefault()
	if store == nil {
		t.Fatal("the hermetic recall store did not open")
	}
	defer store.Close()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if path, ok := recallRoE(store.DB(), cwd); ok {
		t.Errorf("a recalled ROE.md leaked into the tests: %q", path)
	}
}
