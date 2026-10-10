# Security policy

blkChain executes commands, reaches network targets, and analyzes hostile input as its normal
function. That makes the line between a vulnerability and documented behavior worth stating
explicitly before anything else.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a
vulnerability**. This opens a private advisory visible only to the maintainer.

Do not open a public issue or pull request for a security report, and do not post the detail in a
discussion.

A useful report names the invariant it defeats, the version or commit it was found on, and the
shortest sequence that reproduces it. A proof of concept against a target you own or a local
fixture is welcome. Do not include data obtained from a third party, and do not test against a
system you are not authorized to test in order to demonstrate a finding here.

The project is maintained by one person. Expect an acknowledgement within a week. A fix lands on
`main` with a regression test in the suite that covers its area.

## Supported versions

`main` is where a fix lands. The latest tagged release, built from a commit on `main`, is the only
supported release; an earlier tag gets no backport. A report should name the release it was found
on, or the commit when it was found on a build of `main`.

## In scope

The security invariants are documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). A defect that defeats one of them is in scope. In
particular:

- A target reached that the active rules of engagement do not authorize, including through DNS
  resolution, a redirect, a subresource, or a hostname whose address resolves inward. An empty or
  ambiguous scope must fail closed.
- A command the gate should deny that executes, or a path that reaches execution without the gate.
- Target-controlled data gaining authority: page content, a response, a file, corpus text, or tool
  output that selects a target, arms a task, authorizes an action, or executes as code.
- Target-controlled data reaching operator files, credentials, local services, or an unrelated
  network destination.
- Escape from the isolated runner, or a worker reaching a resource its scope excludes.
- An SSRF guard bypass in `blk add <url>`, including a redirect hop that is not revalidated or a
  rebind between validation and connection.
- A secret leaking through a log, report, transcript, evidence record, or an unrelated request.
- A resource bound or the operator stop control failing to hold.
- A sealed policy accepted for a resume that changes its scope, permitted actions, limits, or
  declared foothold.

## Not a vulnerability

- The tool performing active or state-changing testing without a per-action prompt when the rules of
  engagement authorize it. Per-action confirmation is not the control; the policy is.
- The embedding server listening on loopback without authentication. That is the documented
  single-user local model. Reachability from another host is a deployment change, not a defect in
  this repository.
- The corpus containing exploit payloads, prompt-injection strings, and special tokens. That content
  is the data set. A report is in scope only if such text gains authority rather than remaining
  data.
- A local service reachable by a process already running as the operator on the operator's own
  machine.
- Findings that require the operator to run the tool against a system they were not authorized to
  test.
- Dependency advisories with no reachable call path. `govulncheck` runs in the build; a report that
  contradicts it should say which call path reaches the vulnerable symbol.

## Using this project

The operator's authorization for a given target is the premise this tool runs on. It does not verify
that authorization and cannot grant it. Running it against systems you have no permission to test is
unlawful in most jurisdictions and is outside both the intended use and the license. The software
is provided without warranty under the terms in [LICENSE](LICENSE).
