package main

import "blkchain/cli/internal/engagement"

// cloudazureexec.go is the Azure cloud surface executor. It embeds cloudExecutor,
// so it inherits the cloud Run (cloud recon driver + cloud-specific correlation of
// metadata-credential, storage, and IAM findings) and the generic non-recon paths;
// it contributes only the Azure-refined recon ladder and its registration. The
// per-CSP surface is set explicitly on Task.Surface from the target/CSP, so this
// executor fires only for a task carrying SurfaceCloudAzure. Prefix: cloudAzure*.
type cloudAzureExecutor struct {
	cloudExecutor
}

func init() {
	registerExecutor(engagement.SurfaceCloudAzure, func(d engageDeps) surfaceExecutor {
		return cloudAzureExecutor{cloudExecutor{genericExecutor{d: d}}}
	})
	registerLadder(engagement.SurfaceCloudAzure, cloudAzureLadder)
}

var cloudAzureLadder = reconLadder{
	{Index: 0, Name: "public-asset-discovery", Dimensions: []string{"cloud-assets"}},
	{Index: 1, Name: "service-endpoint-fingerprint", Dimensions: []string{"cloud-endpoints", "cloud-services"}},
	{Index: 2, Name: "imds-blob-iam-probe", Dimensions: []string{"azure-imds", "azure-blob", "cloud-iam"}},
	{Index: 3, Name: "finding-driven", Dimensions: []string{"cloud-findings"}},
}
