# Cloud surface

The cloud surface assesses exposure and identity attack paths across AWS, Azure,
and GCP. It maps public assets, fingerprints service endpoints, probes the
metadata and IAM layer for temporary credentials and effective permissions, and
builds a principal-to-permission-to-resource chain.

Executors: `cli/cloudexec.go` with the per-CSP `cli/cloudawsexec.go`,
`cli/cloudgcpexec.go`, `cli/cloudazureexec.go`. Persona: `cloud` in
`cli/domains.go`. Surfaces: `SurfaceCloud`, `SurfaceCloudAWS`, `SurfaceCloudGCP`,
`SurfaceCloudAzure`.

## Capabilities

Discovery and correlation (all three providers):

- Discover public cloud assets, fingerprint service endpoints, and probe the
  metadata and IAM layer, refined per provider: AWS probes the IMDS endpoint
  `169.254.169.254` for role credentials and S3 for storage exposure; GCP probes
  GCP metadata, GCS, and IAM; Azure probes Azure IMDS, Blob storage, and IAM.
- Correlate discovered evidence into cloud findings: metadata-credential
  exposure, storage exposure, and IAM misconfiguration.
- Enumerate from the actual vantage, test public exposure first, then follow
  approved SSRF or foothold paths to metadata, temporary credentials, effective
  permissions, and reachable resources, prioritizing privilege escalation,
  cross-account or cross-tenant access, exposed storage, and control-plane paths.

Provider CLIs:

- AWS operations use the `aws` CLI; GCP operations use the `gcloud` CLI. Azure has
  no CLI in the runner, so its metadata and storage tiers are probed with `curl`
  and `nmap` only.
- A provider CLI is authorized by a separately approved cloud identity (an
  operator approval tied to engagement evidence and a credential file path on a
  foothold that covers the matching cloud surface), not by a network target, so a
  command under an approved identity is exempt from the no-target fail-closed and
  is bounded instead by the operation and flag rules below.
- Audited read-only operations run during recon without arming: for AWS,
  operations beginning `describe-`, `list-`, `get-`, `head-`, `lookup-`, or
  `search-`; for GCP, `projects list`/`describe`, `services list`,
  `compute instances list`/`describe`, `iam service-accounts list`, and
  `storage buckets list`. Any other (mutating) operation requires an armed
  exploit or post-exploitation task.
- The gate denies, for `aws`: `--cli-input-json` and `--cli-input-yaml` (they
  supply every parameter from a file the scope check cannot see); the
  identity-override flags `--endpoint-url`, `--profile`, `--no-sign-request`, and
  `--debug`, and the `configure` and `sso` subcommands; operations that run a
  command on a host, open a tunnel, or launch an instance (`start-session`,
  `start-port-forwarding-session`, `send-command`, `execute-command`,
  `send-ssh-public-key`, `run-instances`, `start-command-execution`); and `cp`,
  `mv`, and `sync` (they take a local path the file-access bound cannot see, with
  `s3api get-object --outfile` available instead). For `gcloud`: the
  identity-override flags (`--account`, `--impersonate-service-account`,
  `--access-token-file`, `--credential-file-override`, and similar) and the
  `auth`, `config`, `components`, `alpha`, `beta`, `ssh`, `scp`, and
  `start-iap-tunnel` subcommands.
- The approval does not copy secret bytes into the workspace; the runner cannot
  verify the file's contents or identity on the remote host, and the CLI cannot
  prove every operation stays in one account or project. Credentials are never
  copied into evidence; redacted identity and permission proof is preserved
  instead.

Public exposure is assessed from an external vantage; the metadata and credential
path typically runs after a foothold. SSH and command carriers cover the AWS and
GCP surfaces, and approving a cloud identity on that foothold enables the provider
CLI.

## Future expansion

- Azure CLI support in the runner, with the same per-operation denials and
  approved-identity gating as the `aws` and `gcloud` CLIs, so the Azure metadata
  tier can lead into authenticated provider operations rather than stopping at
  `curl` probes.
- Deeper AWS coverage: the IAM privilege-escalation path classes (for example
  `iam:PassRole` chains) as named finding-driven dimensions with their own
  arm-gated tasks.
- Cross-account and cross-tenant assumption as an explicit step.
- Control-plane and serverless coverage (functions, event sources) as dedicated
  dimensions rather than finding-driven probes.

The shared engagement model (the command gate, the Auto and Safe arming modes,
vantage reachability, the isolated runner, foothold carriers, and evidence
recording) is described in [the index](README.md).
