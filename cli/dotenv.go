package main

import (
	"os"
	"path/filepath"
	"strings"
)

// dotenv.go loads the project's .env into the process environment at startup,
// so commands that read config directly from os.Getenv (newOMLX in llm.go, for
// example) see it without the operator manually exporting vars. Real environment
// values always win over .env. Nothing here ever logs a value.

// parseDotenvPairs parses every KEY=value line from a .env byte slice: it
// skips blank lines and comments, tolerates a leading `export `, trims
// surrounding whitespace, and strips one layer of matching single or double
// quotes. The last occurrence of a key wins.
func parseDotenvPairs(data []byte) map[string]string {
	pairs := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				v = v[1 : len(v)-1]
			}
		}
		pairs[k] = v
	}
	return pairs
}

// applyPairs sets each pair into the process environment, never overwriting a
// key the process already has (real environment wins over .env). It also
// aliases OMLX_API to OMLX_API_KEY when the project's .env stores the oMLX key
// under the old name but no OMLX_API_KEY is present, since newOMLX() (llm.go)
// reads OMLX_API_KEY. Values are never logged.
func applyPairs(pairs map[string]string) {
	if v, ok := pairs["OMLX_API"]; ok {
		if _, ok := pairs["OMLX_API_KEY"]; !ok {
			pairs["OMLX_API_KEY"] = v
		}
	}
	for k, v := range pairs {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

// applyEnvFile reads <root>/.env, if present, and applies it via applyPairs.
// A missing file or read error is silently ignored.
func applyEnvFile(root string) {
	data, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		return
	}
	applyPairs(parseDotenvPairs(data))
}

// loadProjectEnv best-effort loads the project's .env into the process
// environment so commands like `blk ask` work without the operator manually
// exporting keys. It never fails the program: a project root that cannot be
// located is silently ignored, same as a missing .env.
func loadProjectEnv() {
	root, err := projectRoot()
	if err != nil {
		return
	}
	applyEnvFile(root)
}
