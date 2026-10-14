package main

import (
	"net"
	"net/netip"
)

// clientVantage says whether the caller of one chat turn is a local process
// already holding the operator's privileges.
//
// Two turn options grant the caller the operator's own reach and are refused to
// any other caller: tool_host local runs the terminal and process tools
// directly on the host, outside the sandbox container, and browser_cdp hands
// the agent the operator's signed-in browser session.
//
// The zero value is vantageRemote, so a transport that does not establish its
// caller's vantage is refused rather than trusted. That is the whole point of
// the type: the fact is per transport and per request, not per process, so
// adding a transport cannot inherit another transport's trust.
type clientVantage int

const (
	// vantageRemote is the zero value: the caller is not known to be local.
	vantageRemote clientVantage = iota
	// vantageLocal is a caller proven to be a local process. Two transports
	// establish it: stdio, whose client is the process that spawned this one,
	// and a loopback HTTP request to a loopback-bound server, which is what
	// serveServer.callerVantage decides.
	vantageLocal
)

// checkChatVantage refuses the two operator-reach options to a caller that is
// not local, and validates a browser endpoint that is allowed. It is the single
// enforcement point for both transports.
func checkChatVantage(v clientVantage, toolHost, browserCDP string) error {
	if toolHost == chatToolHostLocal && v != vantageLocal {
		return errChatLocalHostRefused
	}
	if browserCDP == "" {
		return nil
	}
	if v != vantageLocal {
		return errChatBrowserCDPRefused
	}
	if len(browserCDP) > mcpChatMaxBrowserCDP {
		return usageErr("chat: browser_cdp exceeds %d bytes", mcpChatMaxBrowserCDP)
	}
	if err := webValidateCDPEndpoint(browserCDP); err != nil {
		return usageErr("chat: %s", err)
	}
	return nil
}

// vantageForRemoteAddr reads an HTTP request's peer address. Only a loopback
// peer is local. An address this code cannot parse is remote, so a transport
// that reports an unexpected shape is refused rather than trusted.
func vantageForRemoteAddr(addr string) clientVantage {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return vantageRemote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return vantageRemote
	}
	return vantageLocal
}
