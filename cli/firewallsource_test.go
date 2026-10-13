package main

import "testing"

func TestSourcePortHTTPResponseNeedsFinalHeaders(t *testing.T) {
	for _, output := range []string{
		"HTTP/1.1 100 Continue\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n",
		"noise\nHTTP/1.1 200 OK\r\n\r\n",
	} {
		if sourcePortHTTPResponse(output) {
			t.Fatalf("unverified HTTP response accepted: %q", output)
		}
	}
	if !sourcePortHTTPResponse("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n") {
		t.Fatal("complete authentication response was not accepted")
	}
	if !sourcePortHTTPResponse("HTTP/2 200\r\ncontent-length: 0\r\n\r\n") {
		t.Fatal("complete HTTP/2 response was not accepted")
	}
}

func TestSourcePortHTTPCheckRejectsDuplicateOrRangedPorts(t *testing.T) {
	base := []string{"-q", "--silent", "--show-error", "--include", "--noproxy", "*", "--connect-timeout", "3", "--max-time", "8"}
	for _, suffix := range [][]string{
		{"--local-port", "0", "--local-port", "53", "http://192.0.2.10/"},
		{"--local-port", "53-54", "http://192.0.2.10/"},
	} {
		if err := validateCurlSourcePort(append(append([]string(nil), base...), suffix...)); err == nil {
			t.Errorf("ambiguous source-port route accepted: %v", suffix)
		}
	}
}
