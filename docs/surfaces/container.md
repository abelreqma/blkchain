# Container surface

The container surface assesses Kubernetes and container runtime environments.
From an external vantage it maps exposed control-plane and runtime surfaces; from
an in-cluster identity it enumerates RBAC, service accounts, privileged workloads,
and the configurations that allow a pod to escape to the node or the cluster.

Executor: `cli/containerexec.go`. Persona: `containerPersona` (the `k8s` persona
in `cli/domains.go` is its sibling for `k8s`-kind tasks). Surface:
`SurfaceContainer`.

## Capabilities

- Discover exposed surfaces: API server, kubelet, etcd, and runtime sockets.
- Enumerate RBAC and service accounts for the active identity.
- Discover privileged workloads and cluster misconfiguration.
- Probe escape vectors: hostPath mounts, host namespaces, and privileged
  settings.
- Prioritize by vantage: at an external vantage, exposed control-plane and
  anonymous access; from an in-cluster foothold, service-account token
  permissions, privileged workloads, hostPath and host-namespace mounts, and
  escape paths.
- Run `curl` and `nmap` for recon, and `kubectl` for cluster interaction.
  `kubectl` is exploit-tier and arm-gated: the API endpoint is named as
  `--server` so the scope check reads it; a kubeconfig is denied (it can carry an
  exec credential plugin); the `exec`, `run`, `attach`, `debug`, `cp`,
  `port-forward`, and `proxy` verbs are denied (the first group reintroduces a
  shell behind the gate, and `port-forward` and `proxy` hide the destination from
  the scope check); the mutating verbs are permitted as authorized exploit
  actions governed by arming. `docker` and `crictl` are host runtimes and are not
  in the worker.
- Delegate dependency and container-image CVE work to a `vuln-analysis` task
  carrying this task as its basis, rather than scanning inline, so the scanner
  persona owns OSV and Grype and the advisory records.
- Map each identity's allowed verbs and resources to concrete actions, and record
  the identity, resource, permission, request and response, and the boundary
  crossed, redacting token values.

Discovery is read-only. Arm-gated `kubectl` actions validate workload execution,
token access, privilege escalation, or escape. The surface is reached from an
external vantage for control-plane exposure and from an in-cluster foothold for
the rest; SSH and command carriers cover it, so a `kubectl exec`-style access
path can itself be the command carrier.

## Future expansion

- Direct kubelet and etcd interaction steps (the read-only kubelet API, etcd
  secret extraction where exposed) as named capabilities, given discovery already
  finds those surfaces.
- A pod-to-cloud-metadata path wired to the cloud surface, so an in-cluster
  foothold that reaches the node metadata service chains into the AWS, GCP, or
  Azure IAM path.
- RBAC path computation over the enumerated bindings as a code-owned query.
- Admission-controller and network-policy bypass coverage.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
