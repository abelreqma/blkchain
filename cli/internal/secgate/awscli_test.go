package secgate

import "testing"

// TestAwsExecAndTunnelOperationsDenied keeps the AWS CLI an API client, not a
// way onto a host. A session or a command execution runs code on an instance,
// and a port-forwarding session puts the far end outside the scope check.
func TestAwsExecAndTunnelOperationsDenied(t *testing.T) {
	for _, args := range [][]string{
		{"ssm", "start-session", "--target", "i-123"},
		{"ssm", "start-port-forwarding-session", "--target", "i-123"},
		{"ssm", "send-command", "--document-name", "AWS-RunShellScript"},
		{"ecs", "execute-command", "--command", "/bin/sh"},
		{"ec2-instance-connect", "send-ssh-public-key", "--instance-id", "i-123"},
		{"ec2", "run-instances", "--image-id", "ami-1"},
		{"--endpoint-url", "https://192.0.2.10", "ssm", "START-SESSION"},
		{"s3", "cp", "s3://bucket/key", "/etc/passwd"},
		{"s3", "sync", "s3://bucket", "/etc"},
		{"s3", "mv", "s3://bucket/key", "local"},
	} {
		denied(t, "aws "+join(args), Classify(Command{Binary: "aws", Args: args}))
	}
}

// TestAwsApiOperationsAllowed keeps enumeration and the mutating operations an
// armed task may be authorized to run.
func TestAwsApiOperationsAllowed(t *testing.T) {
	for _, args := range [][]string{
		{"--endpoint-url", "https://192.0.2.10", "sts", "get-caller-identity"},
		{"--endpoint-url", "https://192.0.2.10", "iam", "list-roles"},
		{"--endpoint-url", "https://192.0.2.10", "s3api", "list-buckets"},
		{"--endpoint-url", "https://192.0.2.10", "s3api", "get-object", "--bucket", "b", "--key", "k", "--outfile", "obj"},
		{"--endpoint-url", "https://192.0.2.10", "iam", "attach-role-policy", "--role-name", "r"},
		{"--endpoint-url", "https://192.0.2.10", "lambda", "list-functions"},
	} {
		allowed(t, "aws "+join(args), Classify(Command{Binary: "aws", Args: args}))
	}
}

// TestAwsCliInputAndOutfileBounds closes the config-indirection path, where a
// file supplies every parameter including the endpoint, and bounds the output.
func TestAwsCliInputAndOutfileBounds(t *testing.T) {
	for _, args := range [][]string{
		{"s3api", "list-buckets", "--cli-input-json", "own.json"},
		{"s3api", "list-buckets", "--cli-input-json=own.json"},
		{"s3api", "list-buckets", "--cli-input-yaml", "own.yaml"},
	} {
		if _, bad := FileAccessViolation(Command{Binary: "aws", Args: args}); !bad {
			t.Errorf("aws %v should be denied as config indirection", args)
		}
	}
	if _, bad := FileAccessViolation(Command{Binary: "aws",
		Args: []string{"s3api", "get-object", "--outfile", "/etc/passwd"}}); !bad {
		t.Error("aws --outfile outside the scratch directory should be refused")
	}
	if arg, bad := FileAccessViolation(Command{Binary: "aws",
		Args: []string{"s3api", "get-object", "--outfile", "obj.bin"}}); bad {
		t.Errorf("aws --outfile in the scratch directory should pass, refused %q", arg)
	}
}

// TestAwsEndpointIsScopeChecked proves the endpoint is what the scope check
// reads, so an operation against an endpoint outside scope is refused.
func TestAwsEndpointIsScopeChecked(t *testing.T) {
	hosts, _, ok := ExtractTargetSet(Command{Binary: "aws",
		Args: []string{"--endpoint-url", "https://192.0.2.10", "sts", "get-caller-identity"}})
	if !ok || len(hosts) != 1 || hosts[0] != "192.0.2.10" {
		t.Fatalf("aws endpoint not extracted: %v %t", hosts, ok)
	}
	s := mustScope(t, "192.0.2.0/24\n")
	if !s.InScope(hosts[0]) {
		t.Fatal("an in-scope aws endpoint should pass")
	}
	out, _, ok := ExtractTargetSet(Command{Binary: "aws",
		Args: []string{"--endpoint-url", "https://198.51.100.9", "sts", "get-caller-identity"}})
	if !ok || len(out) != 1 || s.InScope(out[0]) {
		t.Fatalf("an out-of-scope aws endpoint was not refused: %v %t", out, ok)
	}
}
