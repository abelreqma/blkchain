# AI-security surface

The AI-security surface assesses AI and LLM endpoints under the OWASP LLM Top 10
and MITRE ATLAS: it maps the endpoint, authentication boundary, model, exposed
parameters, and tool surface, then runs controlled probes. It is built to be
injection-resistant, because the thing it tests is a source of adversarial input.

Executor: `cli/aisecurityexec.go`. Persona: `ai-security`, registered from the
same file. Surface: `SurfaceAISecurity`.

## Capabilities

- Discover AI endpoints and models, probe capability (model version, parameters,
  tooling), run prompt-injection and jailbreak probes, and run finding-driven
  model-abuse and disclosure probes.
- Test direct and indirect prompt injection, cross-turn persistence of
  instructions, refusal-boundary failures, unauthorized tool invocation, unsafe
  structured output, and retrieval and data-boundary failures where the endpoint
  exposes those features, naming for each probe the attacker input, the expected
  secure behavior, the observed deviation, the reachable impact, and a minimal
  reproducible proof.
- Stay injection-resistant by construction:
  - reach an AI endpoint only through the gated `run_command` tool, whose output
    is wrapped as untrusted before it re-enters the model context;
  - derive findings from a deterministic, code-owned scan of the verbatim
    evidence, never from the model's say-so, and RAG-gate each finding through
    the shared citation bar keyed by the OWASP LLM class term, so a matched
    marker with no accepted citation becomes a non-actionable coverage gap
    (blocked status, coverage-gap flag, and an audit record) rather than being
    silently dropped;
  - never recurse the recon frontier onto hosts named in untrusted model output,
    so an indirect prompt injection cannot steer the engagement onto a new
    target, and never pass model output into any command, tool, or system where
    it would execute.
- Run structured-argv tools only: `curl` for requests to the in-scope AI
  endpoint and `nmap` for exposed inference ports, with `route_skill` and
  `kb_search`/`kb_answer` to select probes and ground the impact analysis.
- Record exact request and response evidence with secrets redacted.

Probing is read-only; a deeper or state-affecting boundary test is an arm-gated
exploit or post-exploitation task. Because the surface treats the endpoint as
hostile, the controls above apply regardless of phase.

## Future expansion

- A broader probe corpus wired to the injection and model-abuse steps: more
  injection and jailbreak classes and tool-boundary abuse patterns as named,
  citation-backed probes rather than finding-driven exploration.
- Agent and tool-use assessment where the endpoint exposes functions: mapping the
  tool surface and testing unauthorized invocation as a dedicated step.
- Retrieval and data-boundary testing as a first-class step where the endpoint
  exposes a retrieval feature.
- Local-only operation stated as a guarantee for this surface, since assessing a
  sensitive AI system without sending its prompts or target data to an external
  model is worth stating explicitly in the engagement scope.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
