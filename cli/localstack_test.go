package main

import (
	"os"
	"path/filepath"
	"testing"
)

// localstack_test.go holds the gate the opt-in tests share: the ones that need
// the operator's live LLM, retrieval and runner services rather than a fixture.
//
// Those tests must see the same configuration the blk binary sees. Only main()
// calls loadProjectEnv, so a test that retrieves in-process reads the
// compiled-in defaults instead of the project's .env, looks for a collection the
// operator does not have, and fails as though the services were down. Adopting
// the project's values through t.Setenv fixes that without mutating the process
// environment: the values revert when the test ends, so a hermetic test later in
// the same run still sees the defaults it asserts.

// requireLocalStack skips unless the operator opted in, then adopts the
// project's .env for the duration of the test. A real environment value always
// wins, matching applyPairs, so an explicit export still overrides the file.
func requireLocalStack(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") != "1" {
		t.Skip(reason)
	}
	adoptProjectEnv(t)
}

// adoptProjectEnv applies the project's .env to this test only. No value is
// logged: the pairs go straight into the test's environment.
func adoptProjectEnv(t *testing.T) {
	t.Helper()
	root, err := projectRoot()
	if err != nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		return
	}
	for key, value := range parseDotenvPairs(data) {
		if _, set := os.LookupEnv(key); !set {
			t.Setenv(key, value)
		}
	}
}
