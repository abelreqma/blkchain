# Local surface

The local surface covers Linux post-access work: enumerating a host where a shell
has already been gained for privilege-escalation paths, and non-destructive
analysis of a single binary. Its tasks run either in the isolated worker or, when
a foothold is attached, on the foothold host through a carrier.

Executor: `cli/localexec.go`. Personas: `local` for host enumeration,
`target-analysis` for binary inspection, and `exploit-dev` for exploit
development (all in `cli/domains.go`). Surface: `SurfaceLocal` (reachable at the
internal-foothold vantage or higher).

## Capabilities

Host enumeration (`local`):

- Establish host context: uid, groups, hostname, OS, kernel, mounts, and vantage
  (`id`, `whoami`, `hostname`, `uname`, `mount`).
- Enumerate privilege-escalation leads: sudo rights (`sudo -l`), SUID and SGID
  files (`find` with `-perm -4000 -type f`), file capabilities (`getcap`),
  writable service, cron, PATH, and configuration paths, running services,
  listening ports, and credential-bearing files.
- For each lead, state reachability, the required user or group, the exploitable
  primitive, the expected privilege transition, and the smallest proof. `find`
  scans use bounded permission and type predicates with no `-exec` or `-delete`.

Binary analysis (`target-analysis`, read-only, never executes or modifies the
target):

- Gather permissions, ownership, and SUID/SGID bits (`ls -l`, `stat`); file
  capabilities (`getcap`); type and format (`file`); linked libraries and RPATH
  or RUNPATH (`readelf -d`); readable strings (`strings`); symbols, sections, and
  exploit mitigations (`nm`, `readelf`, `objdump`); and version.
- Assess whether the binary is a privilege-escalation vector using `route_skill`
  (a GTFOBins-style playbook) and `kb_search` for known-CVE or abuse techniques,
  and report a verdict with the exact abuse path, chaining an escalation task.

Exploit development (`exploit-dev`):

- Establish the affected build, architecture, input boundary, crash evidence, and
  mitigations; reproduce and minimize the primitive; develop the narrowest proof
  of the boundary crossed. Static inspection uses `file`, `strings`, `nm`,
  `objdump`, `readelf`, and `gdb`, where `gdb` requires `-nx` and cannot attach
  to a process, run a command file, or run the target.

Enumeration and analysis are read-only; validating a privilege gain is an
arm-gated exploit or post-exploitation task that captures before-and-after
identity and cleanup requirements. The surface is reached after initial access,
and SSH and command carriers cover it. On a pivoted local surface a
`target-analysis` task must name its inspection tool by absolute path
(`/usr/bin/file`, not `file`), because this host's PATH and symlinks do not
describe a file on the foothold; a bare name matching the analysis target's own
base name is refused.

## Future expansion

- Credential-store and secret-file enumeration as a named step, given the persona
  already looks for credential-bearing files.
- Kernel and container-runtime exploit-candidate correlation from the enumerated
  kernel version and mounts, chaining into exploit-development tasks.
- A Windows post-access profile; the surface and its enumeration are Linux-shaped
  today.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
