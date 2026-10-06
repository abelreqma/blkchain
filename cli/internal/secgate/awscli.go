package secgate

import "strings"

// awscli.go audits the AWS CLI. Its flag surface is small but its operation
// surface is not: `aws <service> <operation>` reaches hundreds of APIs, so the
// audit denies the operations that open a shell or a tunnel on a host, the
// flags that supply every other parameter from a file, and the bulk transfer
// operations whose local path is positional and therefore unbounded.
//
// Mutating API operations are not denied. State change in a cloud account is an
// authorized exploit action, governed by arming, the per-action confirmation the
// exploit phase forces, and the scope check on the endpoint.

// awsExecOperations are operations that run a command on, or open a tunnel to,
// a host. They re-introduce what the shell and exec-wrapper denials exist to
// prevent, and a port-forwarding session puts the far end outside the scope
// check the way a proxy flag does.
var awsExecOperations = map[string]bool{
	"start-session":                 true,
	"start-port-forwarding-session": true,
	"send-command":                  true,
	"execute-command":               true,
	"send-ssh-public-key":           true,
	"run-instances":                 true,
	"start-command-execution":       true,
}

// awsUnboundedPathOperations take a local filesystem path as a positional
// argument, which the file-access bound cannot see. The API equivalents with a
// bounded flag remain available: s3api get-object writes through --outfile.
var awsUnboundedPathOperations = map[string]bool{
	"cp": true, "mv": true, "sync": true,
}

// awsViolation denies the AWS CLI forms the gate cannot bound. It reads the
// non-flag tokens, because `aws <service> <operation>` places the operation
// after the service and the global flags may be permuted around both.
func awsViolation(name string, args []string) (Decision, bool) {
	if name != "aws" {
		return Decision{}, false
	}
	for _, a := range args {
		if a == "" || a[0] == '-' {
			continue
		}
		op := strings.ToLower(a)
		if awsExecOperations[op] {
			return Decision{
				Allowed: false,
				Reason:  "aws " + a + " runs a command on a host or opens a tunnel, which the gate cannot bound",
			}, true
		}
		if awsUnboundedPathOperations[op] {
			return Decision{
				Allowed:    false,
				Reason:     "aws " + a + " takes a local path as a positional argument, which the file-access bound cannot see",
				Suggestion: "use the API form with a bounded output flag, e.g. s3api get-object --outfile",
			}, true
		}
	}
	return Decision{}, false
}
