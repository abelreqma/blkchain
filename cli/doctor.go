package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/client"
)

// runDoctor reports the health of the whole blkChain stack and its integration
// with Hermes, as a checklist. It never fails hard on a single failing check —
// it prints every result so you can see the complete picture at a glance.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Println(H1.Render("blk doctor"))
	fmt.Println()

	// 1. Project root + what the native stack needs (venv python, docker).
	root, rootErr := projectRoot()
	if rootErr == nil {
		fmt.Printf("%s project root %s\n", check(true), Meta.Render(root))
		py := filepath.Join(root, ".venv", "bin", "python")
		if _, err := os.Stat(py); err == nil {
			fmt.Printf("%s python venv %s\n", check(true), Meta.Render(".venv/bin/python"))
		} else {
			fmt.Printf("%s python venv missing (%s)\n", check(false), Meta.Render(".venv/bin/python"))
		}
		if _, err := exec.LookPath("docker"); err == nil {
			fmt.Printf("%s docker on PATH\n", check(true))
		} else {
			fmt.Printf("%s docker not on PATH %s\n", check(false), Meta.Render("(needed for qdrant)"))
		}
	} else {
		fmt.Printf("%s project root not found — run `blk install` from the project\n", check(false))
	}

	// 2. API + dependencies.
	c := client.NewClient()
	h, err := c.Health()
	if err != nil {
		fmt.Printf("%s blkChain API unreachable %s — try `blk up`\n", check(false), Meta.Render("("+c.BaseURL+")"))
	} else {
		fmt.Printf("%s blkChain API %s %s\n", check(h.Status == "ok"), h.Status, Meta.Render("("+c.BaseURL+")"))
		fmt.Printf("  %s qdrant\n", check(h.Qdrant))
		fmt.Printf("  %s embed_server\n", check(h.EmbedServer))
	}

	// 3. Hermes binary.
	if _, err := exec.LookPath(hermesBin); err == nil {
		fmt.Printf("%s hermes CLI on PATH\n", check(true))
	} else {
		fmt.Printf("%s hermes CLI not on PATH %s\n", check(false), Meta.Render("(blk hermes / ask --agent unavailable)"))
	}

	// 4. Hermes MCP wiring: is the blkchain MCP server registered and enabled?
	cfgPath := hermesConfigPath()
	present, enabled, err := hermesMCPStatus(cfgPath, "blkchain")
	switch {
	case err != nil:
		fmt.Printf("%s hermes config not read %s\n", Meta.Render("?"), Meta.Render("("+cfgPath+")"))
	case !present:
		fmt.Printf("%s blkchain MCP not registered in %s\n", check(false), Meta.Render(cfgPath))
	case !enabled:
		fmt.Printf("%s blkchain MCP present but disabled in %s\n", Caut.Render(Glyph(GlyphWarn)), Meta.Render(cfgPath))
	default:
		fmt.Printf("%s blkchain MCP registered + enabled for Hermes\n", check(true))
	}
	return nil
}

// hermesConfigPath resolves HERMES_HOME/config.yaml, defaulting to ~/.hermes.
func hermesConfigPath() string {
	home := os.Getenv("HERMES_HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".hermes")
		}
	}
	return filepath.Join(home, "config.yaml")
}

// hermesMCPStatus reports whether an MCP server named `name` is registered under
// `mcp_servers:` in the Hermes config, and whether it is enabled (an entry with
// no `enabled:` key defaults to enabled). This is a small indentation-aware scan
// rather than a full YAML parse, kept dependency-free; it is advisory only.
func hermesMCPStatus(path, name string) (present, enabled bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	lines := strings.Split(string(data), "\n")

	inServers := false // inside the top-level mcp_servers: block
	serverIndent := -1 // indent of the entry keys under mcp_servers
	inEntry := false   // inside the target server's block
	enabled = true     // default when no `enabled:` is stated
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if !inServers {
			if indent == 0 && trimmed == "mcp_servers:" {
				inServers = true
			}
			continue
		}
		// A new top-level key ends the mcp_servers block.
		if indent == 0 {
			break
		}
		if serverIndent == -1 {
			serverIndent = indent
		}
		// An entry key at the server-indent level, e.g. "blkchain:".
		if indent == serverIndent {
			if inEntry {
				break // reached the next server; stop scanning the target
			}
			key := strings.TrimSuffix(trimmed, ":")
			if key == name {
				present, inEntry = true, true
			}
			continue
		}
		// Fields inside the target entry (deeper indent).
		if inEntry && indent > serverIndent {
			if strings.HasPrefix(trimmed, "enabled:") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "enabled:"))
				enabled = val == "true"
			}
		}
	}
	return present, enabled, nil
}
