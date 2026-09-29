package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/ragconfig"
)

// runDoctor reports the health of the whole blkChain stack and its integration
// with Hermes, as a checklist. It never fails hard on a single failing check —
// it prints every result so you can see the complete picture at a glance.
func runDoctor(args []string) error {
	fs := newFlagSet("doctor")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	fmt.Println(H1.Render("blk doctor"))
	fmt.Println()

	// 1. Project root + what the native stack needs (venv python, docker).
	root, rootErr := projectRoot()
	if rootErr == nil {
		fmt.Printf("%s project root %s\n", check(true), Meta.Render(root))
		if _, err := os.Stat(venvPython(root)); err == nil {
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
		fmt.Printf("%s project root not found, run `blk install` from the project\n", check(false))
	}

	// 2. Retrieval dependencies and the LLM server.
	cfg := loadConfig()
	rc, err := newRetrievalClient(cfg)
	if err == nil {
		defer rc.Close()
	}
	printDoctorServices(nativeHealth(cfg, rc), cfg, redactedURL(omlxBaseURL()))

	// 3. Hermes binary.
	if _, err := exec.LookPath(hermesBin); err == nil {
		fmt.Printf("%s hermes CLI on PATH\n", check(true))
	} else {
		fmt.Printf("%s hermes CLI not on PATH %s\n", check(false), Meta.Render("(blk hermes / ask --agent unavailable)"))
	}

	// 4. Hermes MCP wiring: is the blkchain MCP server registered and enabled?
	cfgPath := hermesConfigPath()
	present, enabled, python, err := hermesMCPStatus(cfgPath, "blkchain")
	switch {
	case err != nil:
		fmt.Printf("%s hermes config not read %s\n", Meta.Render("?"), Meta.Render("("+cfgPath+")"))
	case !present:
		fmt.Printf("%s blkchain MCP not registered in %s\n", check(false), Meta.Render(cfgPath))
	case python:
		fmt.Printf("%s blkchain MCP still runs the removed Python server (python -m blkchain.mcp_server); change its command to %s in %s\n",
			Caut.Render(Glyph(GlyphWarn)), Key.Render("blk mcp"), Meta.Render(cfgPath))
	case !enabled:
		fmt.Printf("%s blkchain MCP present but disabled in %s\n", Caut.Render(Glyph(GlyphWarn)), Meta.Render(cfgPath))
	default:
		fmt.Printf("%s blkchain MCP registered + enabled for Hermes\n", check(true))
	}
	return nil
}

// printDoctorServices prints doctor's service rows, each hint right under the
// rows it refers to: "try blk up" after qdrant and embed_server, and the LLM
// hint after the llm row. llmBase is already redacted.
func printDoctorServices(h *serviceHealth, cfg ragconfig.Config, llmBase string) {
	fmt.Printf("%s qdrant %s\n", check(h.Qdrant), Meta.Render("("+cfg.QdrantGRPCURL+")"))
	fmt.Printf("%s embed_server %s\n", check(h.EmbedServer), Meta.Render("("+cfg.EmbedServerURL+")"))
	if !h.Qdrant || !h.EmbedServer {
		fmt.Printf("  %s\n", Meta.Render("try `blk up`"))
	}
	fmt.Printf("%s llm %s\n", check(h.LLM), Meta.Render("("+llmBase+")"))
	if !h.LLM {
		fmt.Printf("  %s\n", Meta.Render(llmDownHint(h, llmBase)))
	}
}

// hermesHome is HERMES_HOME, defaulting to ~/.hermes.
func hermesHome() (string, error) {
	if home := strings.TrimSpace(os.Getenv("HERMES_HOME")); home != "" {
		return home, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".hermes"), nil
}

// hermesConfigPath is Hermes's config.yaml.
func hermesConfigPath() string {
	home, _ := hermesHome()
	return filepath.Join(home, "config.yaml")
}

// hermesConfigMaxBytes caps how much of the Hermes config doctor reads.
const hermesConfigMaxBytes = 1 << 20

// readHermesConfig reads the Hermes config, which must be a regular file (a
// symlink to one is fine) of at most hermesConfigMaxBytes.
func readHermesConfig(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("the Hermes config is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, hermesConfigMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > hermesConfigMaxBytes {
		return nil, errors.New("the Hermes config is over 1 MiB")
	}
	return data, nil
}

// hermesMCPStatus reports whether an MCP server named `name` is registered under
// `mcp_servers:` in the Hermes config, whether it is enabled (an entry with no
// `enabled:` key defaults to enabled), and whether it still runs the removed
// Python MCP server (blkchain.mcp_server, or the start_mcp.sh that ran it). This
// is a small indentation-aware scan rather than a full YAML parse, kept
// dependency-free; it is advisory only and never writes the file.
func hermesMCPStatus(path, name string) (present, enabled, python bool, err error) {
	data, err := readHermesConfig(path)
	if err != nil {
		return false, false, false, err
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
			if strings.Contains(trimmed, "blkchain.mcp_server") || strings.Contains(trimmed, "start_mcp.sh") {
				python = true
			}
		}
	}
	return present, enabled, python, nil
}
