package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/secgate"
)

type httpFormShell struct {
	url        string
	param      string
	headerFile string
}

func buildFootholdHTTPForm(f *secgate.Foothold) (*footholdTransport, error) {
	form := &httpFormShell{url: f.URL, param: f.Param}
	transport := &footholdTransport{carrier: "curl", form: form, secrets: map[string][]byte{}}
	if f.HeaderEnv != "" {
		header, ok := os.LookupEnv(f.HeaderEnv)
		name, value, valid := strings.Cut(header, ":")
		if !ok || !valid || len(header) > 8192 || strings.IndexFunc(header, func(r rune) bool { return r < 32 || r == 127 }) >= 0 ||
			!validHTTPFormHeaderName(name) || strings.TrimSpace(value) == "" {
			return nil, errors.New("invalid HTTP form-shell authorization header")
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "transfer-encoding", "connection", "content-type", "proxy-authorization":
			return nil, errors.New("HTTP form-shell header changes request routing")
		}
		form.headerFile = footholdSecretDir + "/http-header"
		transport.secrets[form.headerFile] = []byte(header + "\n")
	}
	return transport, nil
}

func validHTTPFormHeaderName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if c != '-' && c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func runHTTPFormStages(ctx context.Context, runner *engageRunner, form *httpFormShell, stages []pipelineStage,
	dir string, limit int, timeout time.Duration, policy *secgate.Policy, rawWorker bool) (runResult, []isolatedStageResult) {
	if runner == nil || form == nil || limit < 1 || timeout < time.Second {
		return runResult{Err: errors.New("HTTP form-shell carrier unavailable")}, nil
	}
	argv := make([][]string, len(stages))
	for i, stage := range stages {
		argv[i] = append([]string{stage.Binary}, stage.Args...)
	}
	receipt, err := newSessionCommand(argv)
	if err != nil {
		return runResult{Err: err}, nil
	}
	args := []string{"-q", "--silent", "--show-error", "--fail", "--globoff", "--noproxy", "*", "--proto", "=http,https",
		"--connect-timeout", "5", "--max-time", strconv.Itoa(int(timeout.Seconds())), "--data-urlencode", form.param + "=" + receipt.text}
	if form.headerFile != "" {
		args = append(args, "--header", "@"+form.headerFile)
	}
	args = append(args, form.url)
	result, outputs := runner.RunScoped(ctx, []pipelineStage{{Binary: "curl", Args: args}}, dir, limit, timeout,
		engageEgressPlan{}, policy, rawWorker, nil)
	if result.Err != nil || len(outputs) != 1 || outputs[0].ExitCode != 0 || outputs[0].Dropped != 0 {
		return runResult{Err: errors.New("HTTP form-shell request failed"), TimedOut: result.TimedOut}, nil
	}
	response, complete, err := receipt.parse([]byte(outputs[0].Stdout), limit)
	if err != nil || !complete {
		return runResult{Err: errors.New("HTTP form-shell response lacks a valid command receipt")}, nil
	}
	result = runResult{Output: response.Output, Stdout: response.Output, ExitCode: response.ExitCode}
	if response.ExitCode != 0 {
		result.Err = fmt.Errorf("exit status %d", response.ExitCode)
	}
	stagesOut := make([]isolatedStageResult, len(stages))
	for i := range stagesOut {
		stagesOut[i].ExitCode = -1
	}
	stagesOut[len(stagesOut)-1] = isolatedStageResult{Stdout: response.Output, ExitCode: response.ExitCode}
	return result, stagesOut
}
