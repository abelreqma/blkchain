package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
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
//
// The message is the only signal for this class, so a 400 whose server message
// echoes request content containing one of these phrases is read as a
// context-window rejection. That is bounded: a failover on a 400 re-sends a
// request the server rejected, it does not repeat an action that already took
// effect.
var contextWindowPattern = regexp.MustCompile(`(?i)context_length_exceeded|maximum context length is \d+|reduce the length of the messages`)

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
	// The blanket net.Error interface is not used: *url.Error satisfies it
	// whatever it wraps, so it would admit a malformed URL, an unsupported
	// scheme and a failed certificate verification. Those recur identically on
	// the next model because every model in a chain uses the same endpoint.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
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

// modelRole names which of a turn's two kinds of model calls a site makes.
type modelRole int

const (
	// roleRouter decides and grades. Its calls are short, deterministic and
	// frequent: action classification, routing, the corpus check, context
	// grading and conversation compression.
	roleRouter modelRole = iota
	// roleAssessment answers. Its calls carry the turn's reasoning: the direct
	// answer, the tool loop and grounded synthesis.
	roleAssessment
)

// maxChainModels bounds one role's chain.
const maxChainModels = 4

// roleChains resolves both roles at once, so the fallback model is resolved
// once per turn rather than once per role (resolveModel may ask the LLM server
// which models it serves).
//
// A model the caller named is the whole chain for both roles. An explicit pick
// is an instruction, and a turn reports the model that answered it, so
// answering from a different model would misreport the turn. Otherwise the
// role's configured model leads and the resolved default follows, so an install
// that configures neither role behaves exactly as one model does today.
func roleChains(cfg ragconfig.Config, explicit string) (router, assessment []string) {
	if id := strings.TrimSpace(explicit); id != "" {
		return []string{id}, []string{id}
	}
	fallback := resolveModel(cfg)
	return chainFor(cfg.RouterModel, fallback), chainFor(cfg.AssessmentModel, fallback)
}

// chainFor orders one role's chain: the configured model, then the fallback,
// with blanks and repeats dropped.
func chainFor(configured, fallback string) []string {
	ids := make([]string, 0, 2)
	for _, id := range []string{configured, fallback} {
		id = strings.TrimSpace(id)
		if id == "" || slices.Contains(ids, id) || len(ids) >= maxChainModels {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// modelChain calls one role's models in order, advancing to the next when a
// call fails for a reason that means the model could not answer (see
// failoverEligible). A one-model chain behaves exactly as that one client.
type modelChain struct {
	ids     []string
	clients []toolLoopModel
}

// newModelChain builds a client per id, in order.
func newModelChain(cfg ragconfig.Config, ids []string) (*modelChain, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("no model configured")
	}
	clients := make([]toolLoopModel, 0, len(ids))
	for _, id := range ids {
		c, err := newOMLX(cfg, id)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return &modelChain{ids: slices.Clone(ids), clients: clients}, nil
}

// primary is the id of the model the chain prefers, which is the model a turn
// reports as having answered it.
func (c *modelChain) primary() string {
	if c == nil || len(c.ids) == 0 {
		return ""
	}
	return c.ids[0]
}

func (c *modelChain) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	var resp *llms.ContentResponse
	var err error
	for i, m := range c.clients {
		resp, err = m.GenerateContent(ctx, msgs, opts...)
		if err == nil || i == len(c.clients)-1 || !failoverEligible(err) {
			return resp, err
		}
	}
	return resp, err
}
