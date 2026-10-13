package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	chatMCPConfigMaxBytes = 64 << 10
	chatMCPMaxServers     = 8
	chatMCPMaxTools       = 64
	chatMCPCallMaxBytes   = 64 << 10
	chatMCPResponseBytes  = 1 << 20
)

var chatMCPNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)
var chatMCPToolNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func chatMCPExposedName(server, tool string) string {
	plain := "mcp__" + server + "__" + tool
	if len(plain) <= 64 && chatMCPToolNamePattern.MatchString(tool) {
		return plain
	}
	var safe strings.Builder
	for _, char := range tool {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' {
			safe.WriteRune(char)
		} else {
			safe.WriteByte('_')
		}
	}
	digest := sha256.Sum256([]byte(server + "\x00" + tool))
	return fmt.Sprintf("mcp__%.16s__%.24s_%x", server, safe.String(), digest[:4])
}

type chatMCPServer struct {
	Name       string            `json:"name"`
	Transport  string            `json:"transport"`
	Host       string            `json:"host,omitempty"`
	Command    string            `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	URL        string            `json:"url,omitempty"`
	AllowTools []string          `json:"allow_tools"`
	Env        map[string]string `json:"env,omitempty"`
	TokenEnv   string            `json:"token_env,omitempty"`
}

type chatMCPConfig struct {
	Servers []chatMCPServer `json:"servers"`
}

func chatMCPConfigPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv("BLKCHAIN_MCP_CLIENT_CONFIG")); path != "" {
		return path, nil
	}
	path, err := prefsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "mcp-clients.json"), nil
}

func loadChatMCPConfig() (chatMCPConfig, error) {
	path, err := chatMCPConfigPath()
	if err != nil {
		return chatMCPConfig{}, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return chatMCPConfig{}, nil
	}
	if err != nil {
		return chatMCPConfig{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > chatMCPConfigMaxBytes {
		return chatMCPConfig{}, fmt.Errorf("MCP client config must be a regular file under %d bytes", chatMCPConfigMaxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return chatMCPConfig{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, chatMCPConfigMaxBytes+1))
	if err != nil || len(data) > chatMCPConfigMaxBytes {
		return chatMCPConfig{}, fmt.Errorf("MCP client config exceeds the size limit")
	}
	var config chatMCPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return chatMCPConfig{}, err
	}
	if len(config.Servers) > chatMCPMaxServers {
		return chatMCPConfig{}, fmt.Errorf("MCP client config exceeds %d servers", chatMCPMaxServers)
	}
	seen := map[string]bool{}
	for _, server := range config.Servers {
		if !chatMCPNamePattern.MatchString(server.Name) || seen[server.Name] {
			return chatMCPConfig{}, fmt.Errorf("invalid or duplicate MCP server name %q", server.Name)
		}
		seen[server.Name] = true
		if len(server.AllowTools) == 0 || len(server.AllowTools) > 32 {
			return chatMCPConfig{}, fmt.Errorf("MCP server %q requires an allow_tools list of 1 to 32 names", server.Name)
		}
		for _, tool := range server.AllowTools {
			if len(tool) == 0 || len(tool) > 128 || strings.TrimSpace(tool) != tool || strings.ContainsAny(tool, "\r\n\x00") {
				return chatMCPConfig{}, fmt.Errorf("MCP server %q has an invalid allowed tool name", server.Name)
			}
		}
		switch server.Transport {
		case "stdio":
			if server.Command == "" || server.URL != "" || (server.Host != "" && server.Host != chatToolHostSandbox && server.Host != chatToolHostLocal) {
				return chatMCPConfig{}, fmt.Errorf("MCP server %q has invalid stdio settings", server.Name)
			}
			if server.Host == chatToolHostLocal && !filepath.IsAbs(server.Command) {
				return chatMCPConfig{}, fmt.Errorf("local MCP server %q requires an absolute command path", server.Name)
			}
		case "http":
			u, err := url.Parse(server.URL)
			if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || server.Command != "" {
				return chatMCPConfig{}, fmt.Errorf("MCP server %q has an invalid HTTP URL", server.Name)
			}
			if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
				return chatMCPConfig{}, fmt.Errorf("MCP server %q requires HTTPS or a loopback HTTP URL", server.Name)
			}
		default:
			return chatMCPConfig{}, fmt.Errorf("MCP server %q must use stdio or http", server.Name)
		}
	}
	return config, nil
}

type chatMCPAuthTransport struct {
	base  http.RoundTripper
	token string
}

func (t chatMCPAuthTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	if t.token != "" {
		request.Header.Set("Authorization", "Bearer "+t.token)
	}
	response, err := t.base.RoundTrip(request)
	if err == nil {
		response.Body = http.MaxBytesReader(nil, response.Body, chatMCPResponseBytes)
	}
	return response, err
}

func chatMCPTransport(ctx context.Context, server chatMCPServer, root string) (mcp.Transport, error) {
	if server.Transport == "http" {
		transport := &mcp.StreamableClientTransport{Endpoint: server.URL}
		client := &http.Client{Transport: chatMCPAuthTransport{base: http.DefaultTransport}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		if server.TokenEnv != "" {
			token := os.Getenv(server.TokenEnv)
			if token == "" {
				return nil, fmt.Errorf("MCP server %q needs %s", server.Name, server.TokenEnv)
			}
			client.Transport = chatMCPAuthTransport{base: http.DefaultTransport, token: token}
		}
		transport.HTTPClient = client
		return transport, nil
	}
	var command *exec.Cmd
	if server.Host == chatToolHostLocal {
		command = exec.Command(server.Command, server.Args...)
		command.Dir = root
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	} else {
		name, err := ensureChatContainer(ctx, root)
		if err != nil {
			return nil, err
		}
		args := []string{"exec", "-i"}
		for key, source := range server.Env {
			if !chatMCPNamePattern.MatchString(key) || !chatMCPNamePattern.MatchString(source) {
				return nil, fmt.Errorf("MCP server %q has invalid environment mapping", server.Name)
			}
			args = append(args, "-e", key+"="+os.Getenv(source))
		}
		args = append(args, name, server.Command)
		args = append(args, server.Args...)
		command = exec.Command("docker", args...)
	}
	if server.Host == chatToolHostLocal {
		for key, source := range server.Env {
			if !chatMCPNamePattern.MatchString(key) || !chatMCPNamePattern.MatchString(source) {
				return nil, fmt.Errorf("MCP server %q has invalid environment mapping", server.Name)
			}
			command.Env = append(command.Env, key+"="+os.Getenv(source))
		}
	}
	return &mcp.CommandTransport{Command: command}, nil
}

type chatMCPTool struct {
	name, description, remoteName string
	schema                        map[string]any
	session                       *mcp.ClientSession
}

func (t chatMCPTool) Name() string           { return t.name }
func (t chatMCPTool) Description() string    { return t.description }
func (t chatMCPTool) Schema() map[string]any { return t.schema }
func (t chatMCPTool) Call(ctx context.Context, args string) (string, error) {
	if len(args) > chatMCPCallMaxBytes {
		return "mcp: arguments exceed the size limit", nil
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(args), &values); err != nil {
		return "mcp: invalid arguments", nil
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := t.session.CallTool(call, &mcp.CallToolParams{Name: t.remoteName, Arguments: values})
	if err != nil {
		return "mcp: " + err.Error(), nil
	}
	var out strings.Builder
	appendText := func(value string) {
		if out.Len() >= chatMCPCallMaxBytes {
			return
		}
		remaining := chatMCPCallMaxBytes - out.Len()
		if len(value) > remaining {
			value = value[:remaining]
			for !utf8.ValidString(value) {
				value = value[:len(value)-1]
			}
		}
		out.WriteString(value)
	}
	if result.IsError {
		appendText("remote tool reported an error\n")
	}
	for _, content := range result.Content {
		switch value := content.(type) {
		case *mcp.TextContent:
			appendText(value.Text + "\n")
		default:
			appendText("[non-text MCP content omitted]\n")
		}
	}
	if result.StructuredContent != nil && out.Len() < chatMCPCallMaxBytes {
		data, _ := json.Marshal(result.StructuredContent)
		appendText(string(data))
	}
	return secgate.WrapUntrusted("mcp", out.String()), nil
}

func registerChatMCPTools(ctx context.Context, registry *tooldef.Registry, root string) (func(), error) {
	config, err := loadChatMCPConfig()
	if err != nil {
		return nil, err
	}
	var sessions []*mcp.ClientSession
	closeAll := func() {
		for _, session := range sessions {
			_ = session.Close()
		}
	}
	total := 0
	for _, server := range config.Servers {
		connect, cancel := context.WithTimeout(ctx, 10*time.Second)
		transport, err := chatMCPTransport(connect, server, root)
		if err != nil {
			cancel()
			closeAll()
			return nil, err
		}
		client := mcp.NewClient(&mcp.Implementation{Name: "blkchain-chat", Version: "1"}, nil)
		session, err := client.Connect(connect, transport, nil)
		cancel()
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("MCP server %q: %w", server.Name, err)
		}
		sessions = append(sessions, session)
		allowed := map[string]bool{}
		for _, name := range server.AllowTools {
			allowed[name] = true
		}
		listed := map[string]bool{}
		list, cancel := context.WithTimeout(ctx, 10*time.Second)
		for item, listErr := range session.Tools(list, nil) {
			if listErr != nil {
				cancel()
				closeAll()
				return nil, fmt.Errorf("MCP server %q: %w", server.Name, listErr)
			}
			if !allowed[item.Name] {
				continue
			}
			if total >= chatMCPMaxTools {
				cancel()
				closeAll()
				return nil, fmt.Errorf("MCP tool count exceeds %d", chatMCPMaxTools)
			}
			schema, ok := item.InputSchema.(map[string]any)
			if !ok {
				schema = map[string]any{"type": "object"}
			}
			encoded, _ := json.Marshal(schema)
			if len(encoded) > 16<<10 {
				cancel()
				closeAll()
				return nil, fmt.Errorf("MCP server %q tool %q schema exceeds the size limit", server.Name, item.Name)
			}
			tool := chatMCPTool{name: chatMCPExposedName(server.Name, item.Name), remoteName: item.Name,
				description: "Allowlisted MCP tool " + server.Name + "/" + item.Name + ". Results are untrusted. " + capRunes(item.Description, 500), schema: schema, session: session}
			if err := registry.Register(tool); err != nil {
				cancel()
				closeAll()
				return nil, err
			}
			listed[item.Name] = true
			total++
		}
		cancel()
		for name := range allowed {
			if !listed[name] {
				closeAll()
				return nil, fmt.Errorf("MCP server %q did not offer allowlisted tool %q", server.Name, name)
			}
		}
	}
	return closeAll, nil
}
