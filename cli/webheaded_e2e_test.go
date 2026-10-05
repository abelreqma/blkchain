package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
	"github.com/mxschmitt/playwright-go"
)

func headedPointer(ctx context.Context) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:5901")
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	banner := make([]byte, 12)
	if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "RFB 003.008\n" {
		return fmt.Errorf("viewer protocol: %q %v", banner, err)
	}
	if _, err := conn.Write(banner); err != nil {
		return err
	}
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		return err
	}
	if count[0] == 0 || count[0] > 8 {
		return fmt.Errorf("viewer security count %d", count[0])
	}
	methods := make([]byte, count[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	none := false
	for _, method := range methods {
		none = none || method == 1
	}
	if !none {
		return fmt.Errorf("loopback viewer requires unsupported authentication")
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	var status [4]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(status[:]) != 0 {
		return fmt.Errorf("viewer authentication failed")
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	var init [24]byte
	if _, err := io.ReadFull(conn, init[:]); err != nil {
		return err
	}
	name := binary.BigEndian.Uint32(init[20:])
	width, height := int(binary.BigEndian.Uint16(init[:2])), int(binary.BigEndian.Uint16(init[2:4]))
	if name > 4096 || width*height*4 > 8<<20 {
		return fmt.Errorf("viewer frame bounds")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(name)); err != nil {
		return err
	}

	pixelFormat := []byte{0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}
	if _, err := conn.Write(pixelFormat); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{2, 0, 0, 1, 0, 0, 0, 0}); err != nil {
		return err
	}
	request := []byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(request[6:8], uint16(width))
	binary.BigEndian.PutUint16(request[8:10], uint16(height))
	if _, err := conn.Write(request); err != nil {
		return err
	}
	var update [4]byte
	if _, err := io.ReadFull(conn, update[:]); err != nil {
		return err
	}
	rectangles := int(binary.BigEndian.Uint16(update[2:]))
	if update[0] != 0 || rectangles < 1 || rectangles > 50 {
		return fmt.Errorf("viewer framebuffer update invalid")
	}
	sumX, sumY, pixels, total := 0, 0, 0, 0
	for i := 0; i < rectangles; i++ {
		var rect [12]byte
		if _, err := io.ReadFull(conn, rect[:]); err != nil {
			return err
		}
		left, top := int(binary.BigEndian.Uint16(rect[:2])), int(binary.BigEndian.Uint16(rect[2:4]))
		w, h := int(binary.BigEndian.Uint16(rect[4:6])), int(binary.BigEndian.Uint16(rect[6:8]))
		total += w * h * 4
		if binary.BigEndian.Uint32(rect[8:]) != 0 || left+w > width || top+h > height || total > 8<<20 {
			return fmt.Errorf("viewer rectangle bounds or encoding")
		}
		raw := make([]byte, w*h*4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return err
		}
		for at := 0; at < len(raw); at += 4 {
			if raw[at] == 170 && raw[at+1] == 68 && raw[at+2] == 204 {
				sumX += left + (at/4)%w
				sumY += top + (at/4)/w
				pixels++
			}
		}
	}
	if pixels < 1000 {
		return fmt.Errorf("controlled fixture button absent from headed display: pixels=%d", pixels)
	}
	x, y := sumX/pixels, sumY/pixels
	msg := []byte{5, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(msg[2:4], uint16(x))
	binary.BigEndian.PutUint16(msg[4:6], uint16(y))
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	msg[1] = 1
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	msg[1] = 0
	_, err = conn.Write(msg)
	time.Sleep(200 * time.Millisecond)
	return err
}

func TestWebHeadedAssistanceE2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_PW_E2E") != "1" || os.Getenv("BLKCHAIN_PLAYWRIGHT_HEADED") != "1" {
		t.Skip("requires the provisioned headed browser and local viewer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	process, err := exec.CommandContext(ctx, "docker", "exec", "blk-web-browser", "cat", "/proc/1/cmdline").Output()
	if err != nil || !strings.Contains(string(process), "/chrome") || strings.Contains(string(process), "--headless") {
		t.Fatalf("headed browser process unavailable: %q %v", process, err)
	}
	var responses atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/assisted" {
			responses.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"state":"fixture-unlocked"}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>blkChain headed fixture</title><h1>Headed assistance fixture</h1><button id="unlock" style="position:absolute;left:80px;top:100px;width:240px;height:70px;background:rgb(204,68,170)" onclick="fetch('/api/assisted').then(r=>r.json()).then(r=>document.querySelector('#state').textContent=r.state)">Unlock controlled fixture</button><p id="state" style="position:absolute;left:80px;top:180px">fixture-locked</p>`)
	}))
	defer fixture.Close()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := buildEngageGate(ws, scope, secgate.Auto, nil, secgate.NewSessionApprovals(), "", gatePolicy{UnattendedAllow: secgate.NewAllowlist("web-browser:navigate", "web-api:GET")}, nil)
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	create := func(role string) (*webJobBrowser, *webcollect.Service, <-chan struct{}) {
		t.Helper()
		service := webcollect.New(ws.Store, newWebBroker(gate, nil), webanalysis.Analyze)
		service.DiscoveryAllowed = webRedirectOK(gate)
		browser, err := webNewJobBrowser(gate, nil, service, webSessionRole{Name: role}, true)
		if err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		var once sync.Once
		observe := browser.Driver.observe
		browser.Driver.observe = func(o webObservation) error {
			err := observe(o)
			if o.Artifact.Kind == "browser-dom" {
				once.Do(func() { close(ready) })
			}
			return err
		}
		return browser, service, ready
	}
	t.Run("viewer-input-and-capture", func(t *testing.T) {
		browser, svc, ready := create("assisted")
		defer browser.Close()
		browser.Assist = 4 * time.Second
		actor := make(chan error, 1)
		go func() {
			select {
			case <-ready:
			case <-ctx.Done():
				actor <- ctx.Err()
				return
			}
			time.Sleep(200 * time.Millisecond)
			if err := browser.Driver.page.BringToFront(); err != nil {
				actor <- err
				return
			}
			actor <- headedPointer(ctx)
		}()
		if err := browser.Visit(ctx, fixture.URL+"/", "assisted"); err != nil {
			t.Fatal(err)
		}
		if err := <-actor; err != nil {
			t.Fatal(err)
		}
		if browser.Assist != 0 || responses.Load() != 1 {
			t.Fatalf("assistance consumption=%v responses=%d", browser.Assist, responses.Load())
		}
		if err := svc.RecordStage(ctx, "assistance"); err != nil {
			t.Fatal(err)
		}
		snapshot, err := ws.Store.WebSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		captures := 0
		for _, artifact := range snapshot.Artifacts {
			if artifact.Kind == "assisted-browser-dom" {
				captures++
				blob, err := ws.Store.WebBlob(artifact.Hash)
				if err != nil || !artifact.Complete || !strings.Contains(string(blob), ">fixture-unlocked</p>") {
					t.Fatalf("post-assistance DOM missing: %v %s", err, blob)
				}
			}
		}
		if captures != 1 {
			t.Fatalf("assisted captures=%d", captures)
		}
		image, err := browser.Driver.page.Screenshot(playwright.PageScreenshotOptions{Path: playwright.String("/private/tmp/blk-headed-assistance.png")})
		if err != nil || len(image) == 0 {
			t.Fatal("headed screenshot unavailable", err)
		}
		if err := browser.Visit(ctx, fixture.URL+"/second", "assisted"); err != nil {
			t.Fatal(err)
		}
		snapshot, err = ws.Store.WebSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		captures = 0
		for _, artifact := range snapshot.Artifacts {
			if artifact.Kind == "assisted-browser-dom" {
				captures++
			}
		}
		if captures != 1 {
			t.Fatalf("assistance repeated across navigation: %d", captures)
		}
		webVerifyLiveLLM(t, ctx, gate, ws.Store, fixture.URL)
		t.Log("Headed viewer input unlocked the controlled fixture; exact post-assistance DOM and HTTP response persisted; assistance ran once across two navigations")
	})
	t.Run("cancellation", func(t *testing.T) {
		browser, _, ready := create("cancelled")
		defer browser.Close()
		browser.Assist = 20 * time.Second
		runCtx, stop := context.WithCancel(ctx)
		defer stop()
		result := make(chan error, 1)
		go func() { result <- browser.Visit(runCtx, fixture.URL+"/cancel", "cancelled") }()
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		time.Sleep(200 * time.Millisecond)
		started := time.Now()
		stop()
		select {
		case err := <-result:
			if err != context.Canceled || time.Since(started) > 2*time.Second {
				t.Fatalf("cancellation: %v elapsed=%v", err, time.Since(started))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("assistance ignored cancellation")
		}
		if !browser.Driver.page.IsClosed() {
			for attempt := 0; attempt < 20 && !browser.Driver.page.IsClosed(); attempt++ {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if !browser.Driver.page.IsClosed() {
			t.Fatal("cancelled isolated page remains open")
		}
		t.Log("Cancellation ended the assistance wait and closed the isolated page")
	})
}
