package main

import (
	"bufio"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/secgate"
)

func commandSourcePort(c secgate.Command) int {
	switch strings.ToLower(filepath.Base(c.Binary)) {
	case "curl":
		for i, arg := range c.Args {
			if arg == "--local-port" && i+1 < len(c.Args) {
				return mustPort(c.Args[i+1])
			}
			if strings.HasPrefix(arg, "--local-port=") {
				return mustPort(strings.TrimPrefix(arg, "--local-port="))
			}
		}
	case "nmap":
		port, _ := nmapSourcePortArgs(c.Args)
		return port
	}
	return 0
}

func nmapSourcePortArgs(args []string) (int, []string) {
	port := 0
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := ""
		switch {
		case arg == "--source-port" || arg == "-g":
			i++
			if i >= len(args) {
				return 0, nil
			}
			value = args[i]
		case strings.HasPrefix(arg, "--source-port="):
			value = strings.TrimPrefix(arg, "--source-port=")
		case strings.HasPrefix(arg, "-g") && len(arg) > 2:
			value = arg[2:]
		default:
			out = append(out, arg)
			continue
		}
		parsed := mustPort(value)
		if port != 0 || parsed < 1 || parsed > 65535 {
			return 0, nil
		}
		port = parsed
	}
	return port, out
}

func curlSourcePortPresent(args []string) bool {
	for _, arg := range args {
		if arg == "--local-port" || strings.HasPrefix(arg, "--local-port=") {
			return true
		}
	}
	return false
}

func validateCurlSourcePort(args []string) error {
	if len(args) == 0 || args[0] != "-q" {
		return errors.New("source-port HTTP check requires -q first to disable curlrc")
	}
	silent, showError, include, noProxy := false, false, false, false
	portSeen := false
	port, connectTimeout, maxTime, urls := 0, 0, 0, 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-q":
			if i != 0 {
				return errors.New("-q must be the first curl argument")
			}
		case "--silent":
			silent = true
		case "--show-error":
			showError = true
		case "--include":
			include = true
		case "--noproxy", "--connect-timeout", "--max-time", "--local-port", "--resolve":
			i++
			if i >= len(args) {
				return errors.New("source-port HTTP option needs a value")
			}
			value := args[i]
			switch arg {
			case "--noproxy":
				noProxy = value == "*"
			case "--connect-timeout":
				connectTimeout = mustPort(value)
			case "--max-time":
				maxTime = mustPort(value)
			case "--local-port":
				if portSeen {
					return errors.New("duplicate source port")
				}
				portSeen = true
				port = mustPort(value)
			}
		default:
			if strings.HasPrefix(arg, "--local-port=") {
				if portSeen {
					return errors.New("duplicate source port")
				}
				portSeen = true
				port = mustPort(strings.TrimPrefix(arg, "--local-port="))
				continue
			}
			if strings.HasPrefix(arg, "--resolve=") {
				continue
			}
			u, err := url.Parse(arg)
			if err != nil || u.User != nil || u.Hostname() == "" || u.Fragment != "" || u.Scheme != "http" && u.Scheme != "https" {
				return errors.New("source-port HTTP check permits one HTTP URL and audited flags")
			}
			urls++
		}
	}
	if port < 1 || port > 65535 || connectTimeout < 1 || connectTimeout > 3 || maxTime < 1 || maxTime > 10 || urls != 1 || !silent || !showError || !include || !noProxy {
		return errors.New("source-port HTTP check needs one port, one URL, direct GET, headers, and bounded timeouts")
	}
	return nil
}

func sourcePortHTTPResponse(output string) bool {
	if !strings.HasPrefix(output, "HTTP/") || !strings.Contains(output, "\r\n\r\n") {
		return false
	}
	if strings.HasPrefix(output, "HTTP/2 ") {
		output = "HTTP/2.0" + strings.TrimPrefix(output, "HTTP/2")
	}
	if strings.HasPrefix(output, "HTTP/3 ") {
		output = "HTTP/3.0" + strings.TrimPrefix(output, "HTTP/3")
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(output)), nil)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode >= 200 && response.StatusCode <= 599
}

func curlHTTP3Only(args []string) bool {
	http3, include := false, false
	for _, arg := range args {
		if arg == "--http3-only" {
			http3 = true
		}
		if arg == "--include" {
			include = true
		}
	}
	return http3 && include
}
