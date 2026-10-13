package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mxschmitt/playwright-go"
)

func chatVerifiedLocalNode() (string, error) {
	path := strings.TrimSpace(os.Getenv("BLKCHAIN_BROWSER_NODE_PATH"))
	expected := strings.TrimSpace(os.Getenv("BLKCHAIN_BROWSER_NODE_SHA256"))
	if !filepath.IsAbs(path) || len(expected) != 64 {
		return "", fmt.Errorf("signed-in browser requires BLKCHAIN_BROWSER_NODE_PATH and BLKCHAIN_BROWSER_NODE_SHA256")
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 200<<20 {
		return "", fmt.Errorf("local Node executable is unavailable or too large")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return "", fmt.Errorf("local Node executable digest does not match")
	}
	return path, nil
}

func chatCDPStorageState(ctx context.Context, endpoint string) (*playwright.StorageState, error) {
	if err := webValidateCDPEndpoint(endpoint); err != nil {
		return nil, err
	}
	node, err := chatVerifiedLocalNode()
	if err != nil {
		return nil, err
	}
	driverDir := webPlaywrightDriverDir()
	if driverDir == "" {
		return nil, fmt.Errorf("the pinned Playwright driver is unavailable")
	}
	if err := webVerifyPackage(driverDir); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "blk-cdp-driver-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.Symlink(node, filepath.Join(dir, "node")); err != nil {
		return nil, err
	}
	if err := os.Symlink(filepath.Join(driverDir, "package"), filepath.Join(dir, "package")); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pw, err := playwright.Run(&playwright.RunOptions{SkipInstallBrowsers: true, DriverDirectory: dir})
	if err != nil {
		return nil, err
	}
	defer pw.Stop()
	browser, err := pw.Chromium.ConnectOverCDP(endpoint)
	if err != nil {
		return nil, err
	}
	contexts := browser.Contexts()
	if len(contexts) == 0 {
		return nil, fmt.Errorf("CDP browser has no available context")
	}
	state, err := contexts[0].StorageState()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("browser storage state exceeds the size limit")
	}
	return state, nil
}

func chatCDPFilterOrigin(state *playwright.StorageState, origin string) (*playwright.StorageState, error) {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Scheme != "http" && u.Scheme != "https" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("CDP session requires an exact HTTP origin")
	}
	if state == nil {
		return nil, fmt.Errorf("CDP session state is unavailable")
	}
	host := strings.ToLower(u.Hostname())
	filtered := &playwright.StorageState{}
	for _, cookie := range state.Cookies {
		domain := strings.ToLower(cookie.Domain)
		root := strings.TrimPrefix(domain, ".")
		if root == "" || host != root && (!strings.HasPrefix(domain, ".") || !strings.HasSuffix(host, "."+root)) {
			continue
		}
		if cookie.Secure && u.Scheme != "https" {
			continue
		}
		cookie.Domain = host
		filtered.Cookies = append(filtered.Cookies, cookie)
	}
	for _, item := range state.Origins {
		if webSameOrigin(item.Origin, origin) {
			filtered.Origins = append(filtered.Origins, item)
		}
	}
	if len(filtered.Cookies) == 0 && len(filtered.Origins) == 0 {
		return nil, fmt.Errorf("CDP session has no state for the selected origin")
	}
	return filtered, nil
}
