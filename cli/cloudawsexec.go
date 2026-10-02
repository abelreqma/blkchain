package main

import "blkchain/cli/internal/engagement"

// cloudawsexec.go is the AWS cloud surface executor. It embeds cloudExecutor, so
// it inherits the cloud Run (cloud recon driver + cloud-specific correlation of
// metadata-credential, storage, and IAM findings) and the generic non-recon
// paths; it contributes only the AWS-refined recon ladder and its registration.
// The per-CSP surface is set explicitly on Task.Surface from the target/CSP
// (surfaceForKindMap maps a cloud Kind to the generic SurfaceCloud), so this
// executor fires only for a task carrying SurfaceCloudAWS. Prefix: cloudAWS*.
type cloudAWSExecutor struct {
	cloudExecutor
}

func init() {
	registerExecutor(engagement.SurfaceCloudAWS, func(d engageDeps) surfaceExecutor {
		return cloudAWSExecutor{cloudExecutor{genericExecutor{d: d}}}
	})
	registerLadder(engagement.SurfaceCloudAWS, cloudAWSLadder)
}

// cloudAWSLadder refines the generic cloud ladder's metadata/IAM tier for AWS: the
// IMDS endpoint (169.254.169.254) for role-credential theft and S3 for storage
// exposure, probed within scope with the allowlisted curl (the aws CLI is not
// allowlisted). Built on already-allowlisted tools.
var cloudAWSLadder = reconLadder{
	{Index: 0, Name: "public-asset-discovery", Dimensions: []string{"cloud-assets"}},
	{Index: 1, Name: "service-endpoint-fingerprint", Dimensions: []string{"cloud-endpoints", "cloud-services"}},
	{Index: 2, Name: "imds-s3-iam-probe", Dimensions: []string{"aws-imds", "aws-s3", "cloud-iam"}},
	{Index: 3, Name: "finding-driven", Dimensions: []string{"cloud-findings"}},
}
