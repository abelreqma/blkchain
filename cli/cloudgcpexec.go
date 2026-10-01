package main

import "blkchain/cli/internal/engagement"

// cloudgcpexec.go is the GCP cloud surface executor. It embeds cloudExecutor, so it
// inherits the cloud Run (cloud recon driver + cloud-specific correlation of
// metadata-credential, storage, and IAM findings) and the generic non-recon paths;
// it contributes only the GCP-refined recon ladder and its registration. The
// per-CSP surface is set explicitly on Task.Surface from the target/CSP, so this
// executor fires only for a task carrying SurfaceCloudGCP. Prefix: cloudGCP*.
type cloudGCPExecutor struct {
	cloudExecutor
}

func init() {
	registerExecutor(engagement.SurfaceCloudGCP, func(d engageDeps) surfaceExecutor {
		return cloudGCPExecutor{cloudExecutor{genericExecutor{d: d}}}
	})
	registerLadder(engagement.SurfaceCloudGCP, cloudGCPLadder)
}

var cloudGCPLadder = reconLadder{
	{Index: 0, Name: "public-asset-discovery", Dimensions: []string{"cloud-assets"}},
	{Index: 1, Name: "service-endpoint-fingerprint", Dimensions: []string{"cloud-endpoints", "cloud-services"}},
	{Index: 2, Name: "metadata-gcs-iam-probe", Dimensions: []string{"gcp-metadata", "gcp-gcs", "cloud-iam"}},
	{Index: 3, Name: "finding-driven", Dimensions: []string{"cloud-findings"}},
}
