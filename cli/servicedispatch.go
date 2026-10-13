package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
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

type serviceKey struct {
	endpoint   serviceEndpoint
	vantage    string
	sourcePort int
}

type serviceState struct {
	value      string
	observedAt time.Time
}

const serviceEvidenceTTL = time.Hour

type serviceDispatcher struct {
	store     *engagement.Store
	mu        sync.RWMutex
	vantage   func(secgate.Command) string
	label     func(secgate.Command) string
	state     map[serviceKey]serviceState
	attempted map[serviceKey]bool
}

func newServiceDispatcher(store *engagement.Store) *serviceDispatcher {
	return &serviceDispatcher{store: store, state: make(map[serviceKey]serviceState), attempted: make(map[serviceKey]bool)}
}

func attachServiceDispatcher(g *secgate.Gate, store *engagement.Store) {
	d := newServiceDispatcher(store)
	d.vantage = func(c secgate.Command) string {
		foothold := g.EffectiveFoothold()
		if g.Policy == nil || !foothold.Covers(c.Surface) {
			if strings.HasPrefix(c.Binary, "web-") {
				return "web-broker"
			}
			return "worker"
		}
		identity, _ := json.Marshal(foothold)
		hash := sha256.Sum256(identity)
		return fmt.Sprintf("foothold:%x", hash)
	}
	d.label = func(c secgate.Command) string {
		foothold := g.EffectiveFoothold()
		if g.Policy == nil || !foothold.Covers(c.Surface) {
			if strings.HasPrefix(c.Binary, "web-") {
				return "web broker"
			}
			return "worker"
		}
		return foothold.Transport + " on " + foothold.Host
	}
	g.ServiceCheck = d.Check
	g.ServiceObserve = d.Observe
	g.ServiceEnsure = func(ctx context.Context, c secgate.Command) { d.Ensure(ctx, c, g) }
}

func (d *serviceDispatcher) key(c secgate.Command, ep serviceEndpoint) serviceKey {
	key := serviceKey{endpoint: ep, vantage: "worker", sourcePort: commandSourcePort(c)}
	if d.vantage != nil {
		key.vantage = d.vantage(c)
	}
	return key
}

func serviceRecordID(key serviceKey) string {
	value := fmt.Sprintf("%s/%s/%d/%s", key.endpoint.host, key.endpoint.transport, key.endpoint.port, key.vantage)
	if key.sourcePort != 0 {
		value += fmt.Sprintf("/source-port/%d", key.sourcePort)
	}
	id := sha256.Sum256([]byte(value))
	return fmt.Sprintf("service-%x", id)
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
		key := d.key(c, ep)
		if ctx.Err() != nil {
			return "service dispatch: " + ctx.Err().Error()
		}
		state, err := d.portState(ctx, key)
		if err != nil {
			return "service dispatch: cannot read port evidence: " + err.Error()
		}
		validation := key.sourcePort != 0 && strings.EqualFold(filepath.Base(c.Binary), "curl")
		if state != "open" && !(ep.transport == "udp" && state == "open|filtered") && !(validation && state == "candidate") {
			d.mu.RLock()
			attempted := d.attempted[key]
			d.mu.RUnlock()
			if attempted {
				return fmt.Sprintf("service dispatch: %s/%d on %s was not observed open after bounded discovery", ep.transport, ep.port, ep.host)
			}
			return fmt.Sprintf("service dispatch: %s/%d on %s lacks an observed open port; run bounded port discovery first", ep.transport, ep.port, ep.host)
		}
	}
	return ""
}

func (d *serviceDispatcher) portState(ctx context.Context, key serviceKey) (string, error) {
	var stored serviceState
	if d.store != nil {
		var err error
		stored.value, stored.observedAt, err = d.store.ServicePortState(ctx, serviceRecordID(key))
		if err != nil {
			return "", err
		}
	}
	d.mu.RLock()
	state := d.state[key]
	d.mu.RUnlock()
	if state.observedAt.After(stored.observedAt) {
		stored = state
	}
	age := time.Since(stored.observedAt)
	if age < -time.Minute || age > serviceEvidenceTTL {
		return "", nil
	}
	return stored.value, nil
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
		key := d.key(c, ep)
		if ctx.Err() != nil {
			return
		}
		state, err := d.portState(ctx, key)
		if err != nil || state == "open" || ep.transport == "udp" && state == "open|filtered" || key.sourcePort != 0 && state == "candidate" {
			continue
		}
		d.mu.Lock()
		if d.attempted[key] {
			d.mu.Unlock()
			continue
		}
		d.attempted[key] = true
		d.mu.Unlock()
		if strings.HasPrefix(c.Binary, "web-") {
			if probeWebEndpoint(ctx, g, ep) {
				d.mu.Lock()
				d.state[key] = serviceState{value: "open", observedAt: time.Now().UTC()}
				delete(d.attempted, key)
				d.mu.Unlock()
				if g.Audit != nil {
					g.Audit("service-discovery", fmt.Sprintf("%s/%d on %s open by bounded TCP connect from %s", ep.transport, ep.port, ep.host, d.source(c)))
				}
			}
			continue
		}

		scan := "-sT"
		if ep.transport == "udp" {
			scan = "-sU"
		} else if key.sourcePort != 0 {
			scan = "-sS"
		}
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		args := []string{"-n", "-Pn", scan, "-p", strconv.Itoa(ep.port), ep.host}
		if key.sourcePort != 0 {
			args = []string{"-n", "-Pn", scan, "--source-port", strconv.Itoa(key.sourcePort), "-p", strconv.Itoa(ep.port), ep.host}
		}
		probe := secgate.Command{TaskID: c.TaskID, Binary: "nmap", Args: args, Phase: secgate.PhaseRecon, Surface: c.Surface}
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

func (d *serviceDispatcher) source(c secgate.Command) string {
	if d.label != nil {
		return d.label(c)
	}
	return "worker"
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
		if probeLoopbackProxy(ctx, ip, ep.port) && g.Audit != nil {
			g.Audit("service-probe-gap", address+" accepted a loopback proxy CONNECT but is not reachable from the action's worker vantage")
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
	endpoints, discovery, err := serviceRequirement(c)
	name := strings.ToLower(filepath.Base(c.Binary))
	if err != nil || !discovery && name != "nmap" && !(name == "curl" && commandSourcePort(c) != 0) {
		return err
	}
	observations := scanServiceObservations(c, output)
	if name == "nmap" && commandSourcePort(c) != 0 {
		observations = scanSourcePortCandidates(c, output)
	}
	if name == "curl" && commandSourcePort(c) != 0 && len(endpoints) == 1 && sourcePortHTTPResponse(output) {
		observations = []serviceObservation{{endpoint: endpoints[0], state: "open"}}
	}
	if !discovery {
		verified := observations[:0]
		for _, o := range observations {
			if o.state == "open" || o.state == "open|filtered" {
				key := d.key(c, o.endpoint)
				prior, err := d.portState(ctx, key)
				if err != nil || prior != "open" && !(o.endpoint.transport == "udp" && prior == "open|filtered") && !(name == "curl" && key.sourcePort != 0 && prior == "candidate") {
					continue
				}
			}
			verified = append(verified, o)
		}
		observations = verified
	}
	if len(observations) == 0 {
		return nil
	}
	if d.store == nil || c.TaskID == "" {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, o := range observations {
			key := d.key(c, o.endpoint)
			d.state[key] = serviceState{value: o.state, observedAt: time.Now().UTC()}
			delete(d.attempted, key)
		}
		return nil
	}
	evidenceID, err := d.store.RecordEvidence(c.TaskID, output)
	if err != nil {
		return err
	}
	for _, o := range observations {
		key := d.key(c, o.endpoint)
		fields := map[string]string{"vantage": key.vantage, "source": d.source(c)}
		if key.sourcePort != 0 {
			fields["source_port"] = strconv.Itoa(key.sourcePort)
		}
		detail, _ := json.Marshal(fields)
		_, err := d.store.SaveSurface(ctx, engagement.SurfaceRecord{
			ID: serviceRecordID(key), TaskID: c.TaskID, Surface: engagement.Surface(c.Surface),
			Asset: o.endpoint.host, Kind: "service-port", Name: fmt.Sprintf("%s/%d", o.endpoint.transport, o.endpoint.port),
			Value: o.state, Detail: detail, Source: filepath.Base(c.Binary), EvidenceID: evidenceID,
		})
		if err != nil {
			return err
		}
		d.mu.Lock()
		d.state[key] = serviceState{value: o.state, observedAt: time.Now().UTC()}
		delete(d.attempted, key)
		d.mu.Unlock()
	}
	return nil
}
