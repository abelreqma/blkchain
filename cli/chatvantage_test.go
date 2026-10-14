package main

import (
	"errors"
	"strings"
	"testing"
)

// TestVantageZeroValueRefusesTheOperatorsReach is the control the process-wide
// flag could not give: a transport that never establishes its caller's vantage
// gets the zero value, and the zero value refuses.
func TestVantageZeroValueRefusesTheOperatorsReach(t *testing.T) {
	var unset clientVantage
	if err := checkChatVantage(unset, chatToolHostLocal, ""); !errors.Is(err, errChatLocalHostRefused) {
		t.Errorf("tool_host local on an unset vantage: got %v want %v", err, errChatLocalHostRefused)
	}
	if err := checkChatVantage(unset, "", "http://127.0.0.1:9222"); !errors.Is(err, errChatBrowserCDPRefused) {
		t.Errorf("browser_cdp on an unset vantage: got %v want %v", err, errChatBrowserCDPRefused)
	}
}

func TestVantageLocalAllowsBothAndStillValidates(t *testing.T) {
	if err := checkChatVantage(vantageLocal, chatToolHostLocal, ""); err != nil {
		t.Errorf("tool_host local from a local caller: %v", err)
	}
	if err := checkChatVantage(vantageLocal, "", "http://127.0.0.1:9222"); err != nil {
		t.Errorf("browser_cdp from a local caller: %v", err)
	}
	// A local caller does not get an unvalidated endpoint.
	if err := checkChatVantage(vantageLocal, "", "http://evil.example:9222"); err == nil {
		t.Error("an off-loopback browser endpoint was accepted from a local caller")
	}
	long := "http://127.0.0.1:9222/" + strings.Repeat("a", mcpChatMaxBrowserCDP)
	if err := checkChatVantage(vantageLocal, "", long); err == nil {
		t.Error("an oversize browser endpoint was accepted")
	}
}

func TestVantageForRemoteAddr(t *testing.T) {
	for _, c := range []struct {
		addr string
		want clientVantage
	}{
		{"127.0.0.1:54321", vantageLocal},
		{"[::1]:54321", vantageLocal},
		{"192.168.1.10:54321", vantageRemote},
		{"8.8.8.8:443", vantageRemote},
		{"", vantageRemote},
		{"garbage", vantageRemote},
		{"127.0.0.1", vantageRemote}, // no port: not an address this server produced
	} {
		if got := vantageForRemoteAddr(c.addr); got != c.want {
			t.Errorf("%q: got %v want %v", c.addr, got, c.want)
		}
	}
}
