package main

import (
	"context"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

// engageintegrations.go gives one engagement executor's registry the two
// operator instruments the chat path also carries: the outbound MCP tools, each
// wrapped by newGatedMCPTool so a tool that sends a request is authorized by
// the engagement gate, and the out-of-band tools.
//
// Registration has one home so the authorization logic is not restated per
// executor, and each executor's participation is one line. The session setup
// itself is openMCPSessions, which the chat registry also calls: the transport,
// the allowlist and the bounds have one implementation.

// engageMCPWebInstrument names the outbound MCP server that is a web
// instrument. Its tools register only for a task on the web surface. A cloud,
// Active Directory or local-privilege task gains nothing from Burp, so giving
// it those tools widens the surface for no benefit.
//
// The decision keys on the task's surface rather than on which executor is
// running. webExecutor embeds genericExecutor and does not override Run, so
// genericExecutor.Run builds the web surface's registry, and that same function
// is the fallback for every surface with no registered executor. Keying on the
// executor would therefore hand Burp's tools to a cloud task that fell back to
// the generic executor.
const engageMCPWebInstrument = "burp"

// engageMCPUnavailableAction is the audit action recorded when an outbound MCP
// server cannot be opened and the task runs without its tools.
const engageMCPUnavailableAction = "mcp-unavailable"

// openEngageMCPTools opens one session per server and registers every tool
// newGatedMCPTool reports ok for. It returns the closer for the sessions it
// opened, and on an error it has closed them itself.
//
// The sink buffers the gated tools and reg is written only once openMCPSessions
// has returned a nil error. Several of its error returns fire after earlier
// tools have already reached the sink: the check that each server offered every
// allowlisted tool, which runs after that server's loop, the tool-count and
// schema-size bounds, a list error mid-iteration, and any failure on a later
// server. openMCPSessions closes every session it opened before returning any
// of them, so a sink that registered as the walk proceeded would leave those
// tools in reg over closed sessions, and the caller's degrade would then offer
// the model a send tool whose session is dead: the gate would authorize, prompt
// and audit a request the call cannot dispatch.
func openEngageMCPTools(ctx context.Context, reg *tooldef.Registry, servers []chatMCPServer, gate *secgate.Gate, armed bool) (func(), error) {
	// The sandbox workspace is the root the chat path resolves with no explicit
	// tool host, and it is what a stdio server's command runs in. The engagement
	// scratch directory is where run_command executes and is not an MCP
	// workspace.
	root, err := chatWorkspaceRoot(chatToolHostSandbox)
	if err != nil {
		return nil, err
	}
	var gatedTools []tooldef.Tool
	closeMCP, err := openMCPSessions(ctx, servers, root, func(server, remote string, tool tooldef.Tool) error {
		gated, ok := newGatedMCPTool(tool, server, remote, gate, armed)
		if !ok {
			return nil
		}
		gatedTools = append(gatedTools, gated)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, gated := range gatedTools {
		if err := reg.Register(gated); err != nil {
			closeMCP()
			return nil, err
		}
	}
	return closeMCP, nil
}

// registerEngageIntegrations adds the outbound MCP tools and the out-of-band
// tools to one executor's registry, and returns the closer for every session it
// opened. Nothing is registered twice: the caller owns a fresh registry per
// task.
//
// A task whose deps carry no gate or no captured-output store is on the ungated
// executor path and gets neither instrument. Without a gate there is nothing to
// authorize a request tool, and the read and pure tools go with it rather than
// leaving a partly equipped instrument on a path that has no authorization
// machinery at all.
func registerEngageIntegrations(ctx context.Context, reg *tooldef.Registry, d engageDeps, task engagement.Task) (func(), error) {
	if d.Gate == nil || d.Runs == nil {
		return func() {}, nil
	}
	config, err := loadChatMCPConfig()
	if err != nil {
		return nil, err
	}
	var servers []chatMCPServer
	for _, server := range config.Servers {
		if server.Name == engageMCPWebInstrument && task.Surface != engagement.SurfaceWeb {
			continue
		}
		servers = append(servers, server)
	}
	closeMCP := func() {}
	if len(servers) > 0 {
		opened, openErr := openEngageMCPTools(ctx, reg, servers, d.Gate, task.Armed)
		if openErr != nil {
			// A task runs without per-action operator attention, so a failure to
			// equip the instruments costs the task every outbound MCP tool and not
			// the task itself: an engagement whose own work does not depend on Burp
			// still runs when Burp is closed. The sessions open in one pass over
			// every configured server, so the first failure in that pass discards
			// all of them. The chat path keeps its fatal handling, where the
			// failure is immediate feedback to an operator driving the turn.
			//
			// The degradation is recorded, so a task that ran without the tools is
			// distinguishable from one that had them. A failure to record it is
			// fatal, because a silent degradation is what the record exists to
			// prevent.
			if observe := engageTelemetryFromContext(ctx); observe != nil {
				if auditErr := observe(engageMCPUnavailableAction, openErr.Error()); auditErr != nil {
					return nil, auditErr
				}
			}
		} else {
			closeMCP = opened
		}
	}
	kept := false
	defer func() {
		if !kept {
			closeMCP()
		}
	}()
	// The out-of-band tools register for every surface: any surface can be made
	// to call out, and a blind callback from a cloud metadata probe or an Active
	// Directory relay is as much a finding as one from a web parameter.
	//
	// They take no scope check. The interactsh server is the operator's own
	// infrastructure, in the same class as the model server and the vector
	// store, so a check keyed on engagement targets would deny it. Their bounds
	// are the control, and injecting a payload into a target is a separate
	// action the gate authorizes.
	closeOOB, err := registerOOBTools(ctx, reg)
	if err != nil {
		closeOOB()
		return nil, err
	}
	kept = true
	return func() { closeOOB(); closeMCP() }, nil
}
