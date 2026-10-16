package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
	"blkchain/cli/internal/tooldef"
	"blkchain/cli/internal/webacquire"
	"github.com/tmc/langchaingo/llms"
)

const (
	chatMaxTargets    = 4
	chatCommandOutput = 64 << 10
	chatCommandTime   = 60 * time.Second
)

var chatDomainPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]{1,62}\b`)
var chatTargetReferencePattern = regexp.MustCompile(`(?i)\b(?:it|them|there|again|(?:that|same|previous)\s+(?:target|host|server|site|endpoint|network))\b`)

var chatFileExtensions = map[string]bool{
	"css": true, "go": true, "html": true, "jpeg": true, "jpg": true,
	"js": true, "json": true, "lock": true, "md": true, "mod": true,
	"pdf": true, "png": true, "py": true, "sh": true, "sum": true,
	"toml": true, "ts": true, "txt": true, "yaml": true, "yml": true,
}

// chatLocalFile reports whether name is a regular file in the working
// directory, so a request that names a local file is not read as naming a host.
// The name comes from the request, so the lookup goes through os.Root, which
// keeps it inside the working directory even through a symlink.
func chatLocalFile(name string) bool {
	root, err := os.OpenRoot(".")
	if err != nil {
		return false
	}
	defer root.Close()
	info, err := root.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

func chatTargetEntries(question string, history []priorTurn) []string {
	fromText := func(s string) []string {
		var out []string
		seen := map[string]bool{}
		add := func(target string) {
			target = strings.ToLower(strings.TrimSpace(target))
			if target != "" && !seen[target] && len(out) < chatMaxTargets {
				out = append(out, target)
				seen[target] = true
			}
		}
		for _, raw := range contextURLRefs(s, chatMaxTargets) {
			if u, err := url.Parse(raw); err == nil {
				add(u.Hostname())
			}
		}
		for _, field := range strings.Fields(s) {
			field = strings.Trim(field, `[](){}<>"'.,;!?`)
			if address, err := netip.ParseAddr(field); err == nil {
				add(address.String())
				continue
			}
			if prefix, err := netip.ParsePrefix(field); err == nil {
				add(prefix.String())
				continue
			}
			if address, err := netip.ParseAddrPort(field); err == nil {
				add(address.Addr().String())
			}
		}
		for _, host := range chatDomainPattern.FindAllString(s, -1) {
			parts := strings.Split(host, ".")
			if chatFileExtensions[strings.ToLower(parts[len(parts)-1])] {
				continue
			}
			if chatLocalFile(host) {
				continue
			}
			add(host)
		}
		return out
	}
	if targets := fromText(question); len(targets) > 0 {
		return targets
	}
	if !chatTargetReferencePattern.MatchString(question) {
		return nil
	}
	for i := len(history) - 1; i >= 0; i-- {
		if chatType(history[i].Role) == llms.ChatMessageTypeHuman {
			return fromText(history[i].Content)
		}
	}
	return nil
}

func chatTargetScope(ctx context.Context, targets []string) (*secgate.Scope, error) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{In: targets})
	if err != nil {
		return nil, err
	}
	for _, target := range targets {
		if _, err := netip.ParseAddr(target); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(target); err == nil {
			continue
		}
		lookup, cancel := context.WithTimeout(ctx, 3*time.Second)
		addresses, err := net.DefaultResolver.LookupIPAddr(lookup, target)
		cancel()
		if err != nil || len(addresses) > 16 {
			continue
		}
		for _, address := range addresses {
			ip := address.IP
			if ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				if err := scope.PinNetwork([]string{ip.String()}, nil); err != nil {
					return nil, err
				}
			}
		}
	}
	return scope, nil
}

// newChatWebBroker is the turn's web broker. The broker dials from this host,
// so for a caller that is not local it also refuses this host's own addresses,
// as the sandboxed command executor does: a target named in the request cannot
// turn the broker into a client of the operator's local services.
func newChatWebBroker(gate *secgate.Gate, armed webArmedFunc, vantage clientVantage) *webacquire.Broker {
	broker := newWebBroker(gate, armed)
	if vantage == vantageLocal {
		return broker
	}
	allowed := broker.Policy.IPAllowed
	broker.Policy.IPAllowed = func(host string, ip net.IP) bool {
		return !chatHostAddress(ip) && allowed(host, ip)
	}
	return broker
}

// chatHostAddress reports whether ip reaches this host rather than a remote
// one: loopback, unspecified, link-local, multicast, broadcast, or an address
// on one of this host's interfaces. An unreadable interface list counts as a
// match.
func chatHostAddress(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, address := range addresses {
		if local, _, err := net.ParseCIDR(address.String()); err == nil && local.Equal(ip) {
			return true
		}
	}
	return false
}

type chatScopedTool struct {
	tooldef.Tool
	scope *secgate.Scope
}

func (t chatScopedTool) Call(ctx context.Context, args string) (string, error) {
	return t.Tool.Call(withExecutorScope(ctx, t.scope), args)
}

type chatWebDriver struct {
	broker *webacquire.Broker
	live   *webPlaywrightDriver
}

func (d *chatWebDriver) DoBrowser(ctx context.Context, action webBrowserAction, redirectOK webRedirectAuthorizer) (string, error) {
	if d.live == nil {
		live, err := newWebPlaywrightDriver()
		if err != nil {
			return "", err
		}
		live.broker = d.broker
		d.live = live
	}
	return d.live.DoBrowser(ctx, action, redirectOK)
}

func (d *chatWebDriver) DoAPIRequest(ctx context.Context, request webAPIRequest, redirectOK webRedirectAuthorizer) (string, error) {
	if d.live != nil {
		return d.live.DoAPIRequest(ctx, request, redirectOK)
	}
	out, err := d.broker.Fetch(ctx, webacquire.Request{
		Method: request.Method, URL: request.URL,
		Headers: webHeaders(webParseHeaderLines(request.Headers)), Body: []byte(request.Body),
	})
	if err != nil {
		return "", err
	}
	return webBoundOutput(fmt.Sprintf("%d\n\n%s", out.Status, out.Body)), nil
}

func (d *chatWebDriver) Close() {
	if d.live != nil {
		_ = d.live.Close()
	}
}

func newChatToolRegistry(ctx context.Context, rc searcher, cfg ragconfig.Config, cat *skillcat.Catalog, question string, history []priorTurn, opts AnswerOpts) (*tooldef.Registry, func(), error) {
	root, err := chatWorkspaceRoot(opts.ToolHost)
	if err != nil {
		return nil, nil, err
	}
	reg := tooldef.NewRegistry()
	for _, tool := range []tooldef.Tool{newKBSearchTool(rc, cfg), newRouteSkillTool(cat, nil, nil), newChatFileReadTool(root), newChatFileSearchTool(root)} {
		if err := reg.Register(tool); err != nil {
			return nil, nil, err
		}
	}
	switch opts.requiredAction {
	case "file_write":
		err = reg.Register(newChatFileWriteTool(root))
	case "file_patch":
		err = reg.Register(newChatFilePatchTool(root))
	case "terminal":
		err = reg.Register(newChatTerminalTool(root, opts.ToolHost))
		if err == nil && opts.ToolHost != chatToolHostLocal {
			err = reg.Register(newChatProcessTool(root))
		}
	case "process_manage":
		if opts.ToolHost == chatToolHostLocal {
			return nil, nil, fmt.Errorf("process management requires the sandbox tool host")
		}
		err = reg.Register(newChatProcessTool(root))
	case "file_import", "file_export":
		if opts.ToolHost == chatToolHostLocal {
			return nil, nil, fmt.Errorf("file transfer requires the sandbox tool host")
		}
		// Transfer reads and writes this host's working directory, which is the
		// operator's reach, not the sandbox's.
		if opts.vantage != vantageLocal {
			return nil, nil, fmt.Errorf("file transfer reaches this host's files and requires a local caller")
		}
		local, localErr := chatWorkspaceRoot(chatToolHostLocal)
		if localErr != nil {
			return nil, nil, localErr
		}
		if opts.requiredAction == "file_import" {
			err = reg.Register(newChatTransferTool("file_import", local, root, question))
		} else {
			err = reg.Register(newChatTransferTool("file_export", root, local, question))
		}
	}
	if err != nil {
		return nil, nil, err
	}
	closeMCP, err := registerChatMCPTools(ctx, reg, root, opts.vantage)
	if err != nil {
		return nil, nil, err
	}
	if opts.requiredAction == "mcp" {
		configured := false
		for _, name := range reg.Names() {
			configured = configured || strings.HasPrefix(name, "mcp__")
		}
		if !configured {
			closeMCP()
			return nil, nil, fmt.Errorf("native chat: no MCP client tools are configured")
		}
	}
	targets := chatTargetEntries(question, history)
	publicWeb := opts.webEvidence
	if publicWeb == nil {
		publicWeb = &chatWebProvenance{urls: map[string]bool{}}
	}
	allowPublicResearch := opts.requiredAction == "" || opts.requiredAction == "web_search"
	if opts.requiredAction == "web_extract" && loadPrefs().Web {
		if err := reg.Register(newChatWebExtractTool(question, publicWeb)); err != nil {
			closeMCP()
			return nil, nil, err
		}
	}
	if len(targets) == 0 {
		closeBrowser := func() {}
		if opts.requiredAction == "browser_control" || opts.requiredAction == "browser_vision" {
			state, closeState := chatBrowserForOpts(opts)
			closeBrowser = closeState
			if err := reg.Register(newChatBrowserTool(state, root, question, "public", opts.BrowserCDP, chatPublicBroker(), nil, publicWeb)); err != nil {
				closeState()
				closeMCP()
				return nil, nil, err
			}
			if err := reg.Register(newChatBrowserVisionTool(state, cfg)); err != nil {
				closeState()
				closeMCP()
				return nil, nil, err
			}
		}
		if allowPublicResearch && !opts.NoWeb && loadPrefs().Web && !questionHasTargetDetails(question) {
			if err := reg.Register(newChatWebSearchTool(cfg, question, history, publicWeb)); err != nil {
				closeBrowser()
				closeMCP()
				return nil, nil, err
			}
		}
		if allowPublicResearch && !opts.NoWeb && loadPrefs().Web {
			if err := reg.Register(newChatWebExtractTool(question, publicWeb)); err != nil {
				closeBrowser()
				closeMCP()
				return nil, nil, err
			}
		}
		return reg, func() { closeBrowser(); closeMCP() }, nil
	}
	if opts.requiredAction == "web_extract" {
		return reg, closeMCP, nil
	}
	scope, err := chatTargetScope(ctx, targets)
	if err != nil {
		closeMCP()
		return nil, nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		closeMCP()
		return nil, nil, err
	}
	project, _, err := autodetectEngageConfig(cwd)
	if err != nil {
		closeMCP()
		return nil, nil, err
	}
	scratch, err := os.MkdirTemp("", "blk-chat-*")
	if err != nil {
		closeMCP()
		return nil, nil, err
	}
	gate := &secgate.Gate{
		Mode: secgate.Auto, Scope: scope, Scratch: scratch,
		Allow:         secgate.NewAllowlist(externalEngageAllowlist()...),
		NoDestination: secgate.NewAllowlist(scratchReachBinaries()...),
		AutoAction:    func(secgate.Command) bool { return true },
		Episode:       secgate.NewEpisode(secgate.Caps{MaxCommands: 24, MaxOutputBytes: chatCommandOutput, Wall: 3 * time.Minute}, nil),
	}
	attachServiceDispatcher(gate, nil)
	if project != nil {
		gate.ConfigDenied = project.DeniedBinaries
	}
	if err := gate.Start(); err != nil {
		_ = os.RemoveAll(scratch)
		closeMCP()
		return nil, nil, err
	}
	run := newRunCommandToolForTask(gate, chatCommandOutput, chatCommandTime, scratch,
		func() string { return "" }, nil,
		secgate.Command{Phase: secgate.PhaseExploit, Surface: secgate.SurfaceNetwork, Armed: true}, nil)
	armed := func() bool { return true }
	driver := &chatWebDriver{broker: newChatWebBroker(gate, armed, opts.vantage)}
	closeBrowser := func() {}
	if opts.requiredAction == "browser_control" || opts.requiredAction == "browser_vision" {
		state, closeState := chatBrowserForOpts(opts)
		closeBrowser = closeState
		if err := reg.Register(newChatBrowserTool(state, root, question, strings.Join(targets, ","), opts.BrowserCDP, driver.broker, gate, publicWeb)); err != nil {
			closeState()
			driver.Close()
			_ = os.RemoveAll(scratch)
			closeMCP()
			return nil, nil, err
		}
		if err := reg.Register(newChatBrowserVisionTool(state, cfg)); err != nil {
			closeState()
			driver.Close()
			_ = os.RemoveAll(scratch)
			closeMCP()
			return nil, nil, err
		}
	}
	for _, tool := range []tooldef.Tool{chatScopedTool{Tool: run, scope: scope}, newWebAPITool(gate, armed, driver), newWebBrowserTool(gate, armed, driver)} {
		if err := reg.Register(tool); err != nil {
			closeBrowser()
			driver.Close()
			_ = os.RemoveAll(scratch)
			closeMCP()
			return nil, nil, err
		}
	}
	closeOOB, err := registerOOBTools(ctx, reg)
	if err != nil {
		closeOOB()
		closeBrowser()
		driver.Close()
		_ = os.RemoveAll(scratch)
		closeMCP()
		return nil, nil, err
	}
	return reg, func() { closeOOB(); closeBrowser(); driver.Close(); _ = os.RemoveAll(scratch); closeMCP() }, nil
}
