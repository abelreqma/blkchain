package main

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"syscall"
)

// llmStatusPattern matches the status code in the error the OpenAI-compatible
// client returns for a non-200 response. The status does not reach this code
// any other way: the client formats it into the error text and returns an
// untyped error. TestFailoverEligibleOnARealServerError drives a real client
// against a real 503, so a format change in the pinned client fails a test
// rather than silently disabling failover.
var llmStatusPattern = regexp.MustCompile(`API returned unexpected status code: (\d{3})`)

// contextWindowPattern matches the OpenAI-shaped rejection of a request that
// does not fit the model's context window. Its status is 400, which is
// otherwise the request's own fault, so the message is what separates a window
// that is too small from an argument that is wrong.
var contextWindowPattern = regexp.MustCompile(`(?i)context_length_exceeded|maximum context length|reduce the length of the messages`)

// failoverEligible reports whether err means the model, rather than the
// request, could not answer, so the next model in a role's chain is worth
// trying. Four classes qualify: a transport failure, a timeout, an HTTP 5xx,
// and a rejection for exceeding the context window.
//
// Everything else is refused. A cancellation is the caller's answer, and an
// error this code does not recognize may be the request's own fault, so it must
// not cause the turn's work to run a second time against another model. A tool
// denial and a scope refusal are refused by that default: neither is one of the
// four classes.
func failoverEligible(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, context.DeadlineExceeded):
		return true
	}
	var unreachable *llmUnreachableError
	if errors.As(err, &unreachable) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	msg := err.Error()
	m := llmStatusPattern.FindStringSubmatch(msg)
	if m == nil {
		return false
	}
	code, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return false
	}
	if code >= 500 && code <= 599 {
		return true
	}
	return code == 400 && contextWindowPattern.MatchString(msg)
}
