package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

type serviceEndpoint struct {
	host      string
	transport string
	port      int
}

type serviceObservation struct {
	endpoint serviceEndpoint
	state    string
}

type serviceDispatcher struct {
	store     *engagement.Store
	mu        sync.RWMutex
	state     map[serviceEndpoint]string
	attempted map[serviceEndpoint]bool
}

func newServiceDispatcher(store *engagement.Store) *serviceDispatcher {
	return &serviceDispatcher{store: store, state: make(map[serviceEndpoint]string), attempted: make(map[serviceEndpoint]bool)}
}

func attachServiceDispatcher(g *secgate.Gate, store *engagement.Store) {
	d := newServiceDispatcher(store)
	g.ServiceCheck = d.Check
	g.ServiceObserve = d.Observe
	g.ServiceEnsure = func(ctx context.Context, c secgate.Command) { d.Ensure(ctx, c, g) }
}

func (d *serviceDispatcher) Check(ctx context.Context, c secgate.Command) string {
	if d == nil || c.InternalProbe {
		return ""
	}
	endpoints, discovery, err := serviceRequirement(c)
	if err != nil {
		return "service dispatch: " + err.Error()
	}
	if discovery {
		return ""
	}
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			return "service dispatch: " + ctx.Err().Error()
		}
		state, err := d.portState(ctx, ep)
		if err != nil {
			return "service dispatch: cannot read port evidence: " + err.Error()
		}
		if state != "open" && !(ep.transport == "udp" && state == "open|filtered") {
			d.mu.RLock()
			attempted := d.attempted[ep]
			d.mu.RUnlock()
			if attempted {
				return fmt.Sprintf("service dispatch: %s/%d on %s was not observed open after bounded discovery", ep.transport, ep.port, ep.host)
			}
			return fmt.Sprintf("service dispatch: %s/%d on %s lacks an observed open port; run bounded port discovery first", ep.transport, ep.port, ep.host)
		}
	}
	return ""
}

func (d *serviceDispatcher) portState(ctx context.Context, ep serviceEndpoint) (string, error) {
	stored := ""
	if d.store != nil {
		var err error
		stored, err = d.store.ServicePortState(ctx, ep.host, ep.transport, ep.port)
		if err != nil || stored == "closed" || stored == "filtered" {
			return stored, err
		}
	}
	d.mu.RLock()
	state := d.state[ep]
	d.mu.RUnlock()
	if state != "" {
		return state, nil
	}
	return stored, nil
}

func (d *serviceDispatcher) Ensure(ctx context.Context, c secgate.Command, g *secgate.Gate) {
	if d == nil || g == nil || c.InternalProbe {
		return
	}
	endpoints, discovery, err := serviceRequirement(c)
	if err != nil || discovery || len(endpoints) > 8 {
		return
	}
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			return
		}
		state, err := d.portState(ctx, ep)
		if err != nil || state == "open" || ep.transport == "udp" && state == "open|filtered" {
			continue
		}
		d.mu.Lock()
		if d.attempted[ep] {
			d.mu.Unlock()
			continue
		}
		d.attempted[ep] = true
		d.mu.Unlock()
		if strings.HasPrefix(c.Binary, "web-") {
			if probeWebEndpoint(ctx, g, ep) {
				d.mu.Lock()
				d.state[ep] = "open"
				d.mu.Unlock()
				if g.Audit != nil {
					g.Audit("service-discovery", fmt.Sprintf("%s/%d on %s open by bounded TCP connect", ep.transport, ep.port, ep.host))
				}
			}
			continue
		}

		scan := "-sT"
		if ep.transport == "udp" {
			scan = "-sU"
		}
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		probe := secgate.Command{TaskID: c.TaskID, Binary: "nmap", Args: []string{"-n", "-Pn", scan, "-p", strconv.Itoa(ep.port), ep.host}, Phase: secgate.PhaseRecon, Surface: c.Surface}
		decision := g.Authorize(probeCtx, probe)
		if !decision.Allowed {
			cancel()
			continue
		}
		dir, err := os.MkdirTemp(g.Scratch, "service-probe-")
		if err != nil {
			cancel()
			continue
		}
		result := runAuthorized(probeCtx, g, probe.Binary, probe.Args, dir, 64<<10, 12*time.Second, actionOrigin{TaskID: c.TaskID, Surface: c.Surface})
		if result.Err != nil && g.Audit != nil {
			g.Audit("service-probe-gap", ep.host+":"+strconv.Itoa(ep.port)+" :: "+result.Err.Error())
		}
		releaseEngageWorker(ctx, dir)
		_ = os.RemoveAll(dir)
		cancel()
	}
}

func probeWebEndpoint(ctx context.Context, g *secgate.Gate, ep serviceEndpoint) bool {
	if ep.transport != "tcp" || g.Scope == nil {
		return false
	}
	pivoted := g.EffectiveFoothold().Covers(secgate.SurfaceWeb)
	scope := g.Scope
	if pivoted && g.PivotScope != nil {
		scope = g.PivotScope
	}
	var addresses []net.IP
	if ip := net.ParseIP(ep.host); ip != nil {
		addresses = []net.IP{ip}
	} else if pivoted && g.WebLookup != nil {
		resolved, err := g.WebLookup(ep.host)
		if err != nil {
			return false
		}
		addresses = resolved
	} else {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, ep.host)
		if err != nil {
			return false
		}
		for _, address := range resolved {
			addresses = append(addresses, address.IP)
		}
	}
	for i, ip := range addresses {
		if i >= 8 {
			break
		}
		allowed := scope.WebAddressAllowed(ep.host, ip)
		if pivoted && g.PivotScope != nil {
			allowed = scope.PivotWebAddressAllowed(ep.host, ip)
		}
		if !allowed {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		address := net.JoinHostPort(ip.String(), strconv.Itoa(ep.port))
		var conn net.Conn
		var err error
		if pivoted {
			if runtime := runtimeFor(probeCtx); runtime != nil && runtime.runner != nil {
				conn, err = runtime.runner.DialFoothold(probeCtx, address)
			}
		} else {
			conn, err = (&net.Dialer{}).DialContext(probeCtx, "tcp", address)
		}
		cancel()
		if err == nil && conn != nil {
			_ = conn.Close()
			return true
		}
		if probeLoopbackProxy(ctx, ip, ep.port) {
			return true
		}
	}
	return false
}

func probeLoopbackProxy(ctx context.Context, ip net.IP, port int) bool {
	setting := strings.TrimSpace(os.Getenv("BLKCHAIN_WEB_PROXY"))
	if strings.EqualFold(setting, "off") {
		return false
	}
	if setting == "" {
		setting = "127.0.0.1:8080"
	}
	host, proxyPort, err := net.SplitHostPort(setting)
	proxyIP := net.ParseIP(host)
	if err != nil || proxyIP == nil || !proxyIP.IsLoopback() || mustPort(proxyPort) < 1 || mustPort(proxyPort) > 65535 {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", setting)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		return false
	}
	line, err := bufio.NewReaderSize(conn, 1024).ReadSlice('\n')
	fields := strings.Fields(string(line))
	return err == nil && len(fields) >= 2 && (fields[0] == "HTTP/1.1" || fields[0] == "HTTP/1.0") && fields[1] == "200"
}

func (d *serviceDispatcher) Observe(ctx context.Context, c secgate.Command, output string) error {
	if d == nil || c.InternalProbe {
		return nil
	}
	_, discovery, err := serviceRequirement(c)
	if err != nil || !discovery && strings.ToLower(filepath.Base(c.Binary)) != "nmap" {
		return err
	}
	observations := scanServiceObservations(c, output)
	if len(observations) == 0 {
		return nil
	}
	if d.store == nil || c.TaskID == "" {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, o := range observations {
			d.state[o.endpoint] = o.state
		}
		return nil
	}
	evidenceID, err := d.store.RecordEvidence(c.TaskID, output)
	if err != nil {
		return err
	}
	for _, o := range observations {
		key := fmt.Sprintf("%s/%s/%d", o.endpoint.host, o.endpoint.transport, o.endpoint.port)
		id := sha256.Sum256([]byte(key))
		_, err := d.store.SaveSurface(ctx, engagement.SurfaceRecord{
			ID: fmt.Sprintf("service-%x", id), TaskID: c.TaskID, Surface: engagement.Surface(c.Surface),
			Asset: o.endpoint.host, Kind: "service-port", Name: fmt.Sprintf("%s/%d", o.endpoint.transport, o.endpoint.port),
			Value: o.state, Source: filepath.Base(c.Binary), EvidenceID: evidenceID,
		})
		if err != nil {
			return err
		}
		d.mu.Lock()
		d.state[o.endpoint] = o.state
		d.mu.Unlock()
	}
	return nil
}
