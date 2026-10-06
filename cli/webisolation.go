package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
)

type webContainerConfig struct {
	Config struct {
		Image, User string
		Env         []string
	}
	HostConfig struct {
		NetworkMode                string
		Privileged, ReadonlyRootfs bool
		Memory, NanoCpus           int64
		PidsLimit                  *int64
		CapDrop, SecurityOpt       []string
		Binds                      []string
	}
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	}
}

func webCheckContainer(c webContainerConfig, dir string) error {
	fail := errors.New("browser container requires the pinned image, network none, non-root user, read-only root, bounded memory/CPU/PIDs, dropped capabilities and only the driver mount")
	if !strings.HasSuffix(c.Config.Image, "@"+webPinnedDHIImageDigest) || c.Config.User != "1000:1000" || c.HostConfig.NetworkMode != "none" || c.HostConfig.Privileged || !c.HostConfig.ReadonlyRootfs || c.HostConfig.Memory < 128<<20 || c.HostConfig.Memory > 2<<30 || c.HostConfig.NanoCpus <= 0 || c.HostConfig.NanoCpus > 4e9 || c.HostConfig.PidsLimit == nil || *c.HostConfig.PidsLimit <= 0 || *c.HostConfig.PidsLimit > 512 {
		return fail
	}
	for _, v := range c.Config.Env {
		if strings.HasPrefix(v, "NODE_OPTIONS=") && v != "NODE_OPTIONS=" || strings.HasPrefix(v, "NODE_PATH=") && v != "NODE_PATH=/usr/lib/node_modules" {
			return fail
		}
	}
	has := func(v []string, s string) bool {
		for _, x := range v {
			if strings.EqualFold(x, s) {
				return true
			}
		}
		return false
	}
	if !has(c.HostConfig.CapDrop, "ALL") || (!has(c.HostConfig.SecurityOpt, "no-new-privileges") && !has(c.HostConfig.SecurityOpt, "no-new-privileges:true")) {
		return fail
	}
	want, e := filepath.EvalSymlinks(filepath.Join(dir, "package"))
	if e != nil {
		return fail
	}
	mount := false
	for _, m := range c.Mounts {
		if m.Type == "tmpfs" {
			continue
		}
		src, e := filepath.EvalSymlinks(m.Source)
		if e != nil || m.Type != "bind" || m.RW || m.Destination != "/opt/blkchain-playwright/package" || src != want {
			return fail
		}
		mount = true
	}
	if !mount {
		return fail
	}
	return nil
}
func webVerifyContainer(dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bin := os.Getenv("BLKCHAIN_DOCKER_BIN")
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, "inspect", "--format", "{{json .}}", os.Getenv("BLKCHAIN_PLAYWRIGHT_CONTAINER"))
	var buf webLimitedBuffer
	buf.limit = 128 << 10
	cmd.Stdout = &buf
	cmd.Stderr = &webLimitedBuffer{limit: 4096}
	if err := cmd.Run(); err != nil {
		return errors.New("cannot verify browser container isolation")
	}
	var c webContainerConfig
	if json.Unmarshal(buf.Bytes(), &c) != nil {
		return errors.New("invalid container configuration")
	}
	return webCheckContainer(c, dir)
}

type webLimitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *webLimitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func newWebBroker(g *secgate.Gate, armed webArmedFunc) *webacquire.Broker {
	policy := webacquire.Policy{
		Authorize: func(ctx context.Context, r webacquire.Request) error {
			if g == nil {
				return errors.New("web request gate missing")
			}
			if g.Policy != nil && g.PolicyBytesRemaining() == 0 {
				return g.ClaimPolicyBytes(1)
			}
			active := false
			u, _ := webacquire.URL(r.URL)
			if u != nil {
				path := strings.ToLower(u.Path)
				for _, s := range []string{"logout", "delete", "reset", "unsubscribe", "destroy"} {
					for _, part := range strings.Split(path, "/") {
						if part == s {
							active = true
						}
					}
				}
			}
			d := g.AuthorizeAPIRequest(ctx, secgate.APIRequest{Method: r.Method, URL: r.URL, Armed: webArmedOrFalse(armed), Active: active})
			if !d.Allowed {
				return errors.New("request denied: " + d.Reason)
			}
			return nil
		}, IPAllowed: func(ip net.IP) bool { return g != nil && g.Scope != nil && g.Scope.InScope(ip.String()) }}
	if g != nil && g.Policy != nil {
		policy.MaxBodyBytes = g.Policy.OutputBytes
		policy.MaxTotalBytes = g.Policy.TotalBytes
		policy.MaxRequests = g.Policy.MaxCommands
		if g.Policy.MaxActions < policy.MaxRequests {
			policy.MaxRequests = g.Policy.MaxActions
		}
		policy.AccountBytes = g.ClaimPolicyBytes
	}
	return &webacquire.Broker{Policy: policy}
}

type webObservation struct {
	Artifact webanalysis.Artifact
	Body     []byte
	Request  webanalysis.RequestExample
}

func webHeaders(h map[string]string) http.Header {
	out := make(http.Header)
	for k, v := range h {
		out.Set(k, v)
	}
	return out
}
