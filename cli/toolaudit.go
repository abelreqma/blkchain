package main

import "sort"

// toolaudit.go records which catalog binaries have had their full flag surface
// audited, and what the outstanding audits must cover. Only an audited tierEnum
// binary reaches the EXTERNAL-profile allowlist, because an allowlist entry
// authorizes every flag of that binary: an unaudited entry is a code-execution,
// file-write, exfiltration, config-indirection, or scope-bypass surface.
//
// The five classes every audit covers:
//
//  1. code execution: flags or argument forms that run a program
//  2. file write: output and log flags
//  3. file read and exfiltration: flags whose value is a file that is sent or echoed
//  4. config indirection: flags that read options from a file
//  5. target channel: every spelling in which a destination host can be given,
//     including positional, spaced, =value, glued, and bundled forms
var auditedBinaries = map[string]string{
	"nmap":       "secgate: execFlag denies --script and --datadir, unboundedRules requires a port bound, fileaccess bounds -oN/-oX/-oG/-oA/-oS/-oJ/--stylesheet/--resume, targetFlagSpecs scope-checks --proxies",
	"curl":       "secgate: execFlag denies --unix-socket, denyFlags denies -K/--config, writeFlags and dataFlags bound its file flags, targetFlagSpecs scope-checks every proxy flag and denies the glued form",
	"nc":         "secgate: execFlag denies -e/-c and the long exec options in bundled and glued forms, fileaccess bounds -o",
	"ncat":       "secgate: execFlag denies -e/-c/--exec/--sh-exec/--lua-exec in bundled, glued and abbreviated forms",
	"dig":        "secgate: enumConfigDeny denies -f/-k/-y with its value-taking letters accounted for",
	"host":       "secgate/dnsenum_test.go: no file, exec, or config flag; the target is positional and scope-checked",
	"nslookup":   "secgate/dnsenum_test.go: no file, exec, or config flag; the target is positional and scope-checked",
	"whois":      "secgate/dnsenum_test.go: the base image's busybox build has no file, exec, or config flag",
	"traceroute": "secgate/toolgate_test.go: the busybox build has no file, exec, or config flag; the target is positional and -g names a gateway the extractor sees as its own argument",
	"smbclient":  "secgate/smbenum_test.go: execFlag denies -c/--command, smbDeny denies -T/-A/-s/--option/--use-krb5-ccache/--machine-pass, fileaccess bounds -l/--log-basename, enumGluedHostFlag denies a glued -I/-L/-M/-B",
	"rpcclient":  "secgate/smbenum_test.go: shares smbDeny with smbclient, execFlag denies -c/--command, enumGluedHostFlag denies a glued -I",
	"nbtscan":    "secgate/smbenum_test.go: enumConfigDeny denies -f/--file, which reads targets from a file the scope check never sees",
	"showmount":  "secgate/smbenum_test.go: no file, exec, or config flag; the target is positional and scope-checked",
	"ldapsearch": "secgate/netenum_test.go: enumConfigDeny denies -y/-h/-t/-C, fileaccess bounds -f/-T, the target must be an -H URI the scope check can read",
	"snmpwalk":   "secgate/netenum_test.go: enumConfigDeny denies -L/-M/-m with its value-taking letters accounted for",
	"ffuf":       "secgate/httpenum_test.go: execFlag denies -input-cmd/-input-shell, denyFlags denies -config/-request, writeFlags bounds -o/-od/-of/-w/-debug-log, targetFlagSpecs scope-checks -u/-x/-replay-proxy",
	"tcpdump":    "secgate/toolgate_test.go: execFlag denies -z in bundled form, requiredFlags demands a -c packet bound, fileaccess bounds -w/-r/-F, and a host in the capture filter is scope-checked",
	"sslscan":    "secgate/toolgate_test.go: no exec or config flag, fileaccess bounds --xml/--certs/--pk/--ca-certs, the target is positional host:port",
	"openssl":    "secgate/toolgate_test.go: execFlag denies -engine/-provider/-provider-path, denyFlags denies -config, fileaccess bounds -out/-keyout/-in and the certificate and key flags, the target comes from s_client -connect",
	"jq":         "secgate/toolgate_test.go: fileaccess bounds -f/--from-file and denies the two-value --rawfile/--slurpfile whose path the bound would miss; no exec flag and no network destination",
	"file":       "secgate/toolgate_test.go: denyFlags denies -f/--files-from, fileaccess bounds -C/-m; no exec flag and no network destination",
	"strings":    "secgate/toolgate_test.go: execFlag denies --plugin; no write or config flag",
	"nm":         "secgate/toolgate_test.go: execFlag denies --plugin in both dash forms and abbreviated; no write or config flag",
	"objdump":    "secgate/toolgate_test.go: execFlag denies --plugin in both dash forms and abbreviated; no write or config flag",
	"readelf":    "secgate/toolgate_test.go: execFlag denies --plugin; no write or config flag",
	"gdb":        "secgate/toolgate_test.go: execFlag denies -x/-ex/-ix/--command/--eval-command/--init-command/-p/--args/--write, and requiredFlags demands -nx because gdb otherwise runs the init file in HOME, which is the writable executor scratch",
	"john":       "secgate/toolgate_test.go: execFlag denies --external, denyFlags denies --config, fileaccess bounds --pot/--session/--wordlist/--loopback, unboundedRules requires --max-run-time or --max-candidates",
	"klist":      "secgate/toolgate_test.go: fileaccess bounds -c/-k; no exec or config flag and no network destination",
	"sudo":       "secgate/toolgate_test.go: sudoListOnly permits exactly -l, -n -l, -ln and -nl; every operand and every other flag stays denied, and sudo is not installed in the image",
	"hostname":   "secgate/toolgate_test.go: readOnlyForms denies the operand that sets the hostname",
	"mount":      "secgate/toolgate_test.go: readOnlyForms denies every argument, so only the bare listing runs",
	"crontab":    "secgate/toolgate_test.go: readOnlyForms permits exactly -l, so -e, -r and a file operand are denied",
	"getcap":     "secgate/toolgate_test.go: no exec, write, or config flag; it reads the named paths",
	"id":         "secgate/toolgate_test.go: no flag surface of concern; it reports the current identity",
	"whoami":     "secgate/toolgate_test.go: no flag surface of concern",
	"uname":      "secgate/toolgate_test.go: no flag surface of concern",
	"stat":       "secgate/toolgate_test.go: no exec, write, or config flag; it reads the named path",
	"ps":         "secgate/toolgate_test.go: no flag surface of concern in the busybox build",
	"netstat":    "secgate/toolgate_test.go: no flag surface of concern in the busybox build",
	"lsof":       "secgate/toolgate_test.go: no flag surface of concern in the busybox build",
	"aws":        "secgate/awscli_test.go: awsViolation denies the operations that run a command on a host or open a tunnel (ssm start-session, start-port-forwarding-session, send-command, ecs execute-command, send-ssh-public-key, ec2 run-instances) and the bulk transfer operations whose local path is positional and so invisible to the file bound (s3 cp, mv, sync); denyFlags denies --cli-input-json and --cli-input-yaml, which supply every parameter including the endpoint from a file; fileaccess bounds --outfile and --ca-bundle; the destination comes from --endpoint-url, which the extractor reads as a URL, so an operation with no endpoint has no verifiable target. Mutating API operations stay available, governed by arming and the confirmation the exploit phase forces",
	"socat":      "secgate/socat_test.go: socatViolation audits socat by its addresses rather than its flags, permitting only the connect types whose host the scope check can read (TCP, TCP4, TCP6, UDP, OPENSSL and their -CONNECT and -SENDTO forms) plus STDIO, and denying EXEC, SYSTEM, SHELL, OPEN, CREATE, GOPEN, UNIX-*, SOCKS, PROXY, every -LISTEN form, TUN and any unknown keyword; keywords are compared case-folded with - and _ removed, as socat accepts them. socatTargets extracts the host of each end, including a bracketed IPv6 literal, and fails closed on an address with no usable host. Exploit tier, so the phase forces per-action confirmation",
	"masscan":    "secgate/masscan_test.go: masscanViolation denies every file channel in masscan's own normalized spelling, because masscan lowercases a flag name and strips - and _ before comparing it, so --excludefile, --exclude-file, --exclude_file and --EXCLUDEFILE are one flag; requiredFlags demands a port bound and an explicit rate; evidence is the captured stdout. A range target is authorized by Scope.NetworkInScope when one in-scope CIDR covers it",
	"kubectl":    "secgate/toolgate_test.go: execFlag denies the exec, run, attach, debug, cp, port-forward and proxy verbs over every non-flag token, denyFlags denies --kubeconfig because it can carry an exec credential plugin, fileaccess bounds the certificate and cache paths, and the server must be named as --server so the scope check reads it. Exploit tier, so the phase forces per-action confirmation",
}

// pendingAudits are catalog binaries that are present in the image but not yet
// on the EXTERNAL allowlist, with what each audit must still cover. A persona
// may not name one, which TestPersonaPromptsAvoidUnauditedTools enforces.
var pendingAudits = map[string]string{
	"kinit": "the destination is a KDC resolved from the realm through DNS and krb5.conf, so the scope check cannot see it, and a principal of the form user@REALM makes the extractor scope-check the realm as if it were a host. Needs either a realm-aware extractor rule or the execution-location work, with the worker firewall as the enforcing layer meanwhile",
}

// impacketAudit is the audit every impacket entry point shares. The credential
// in its target operand is deliberately left intact, in the argv and in the
// recorded command: these tools take it on the command line by design, and an
// engagement transcript is expected to show exactly what ran.
const impacketAudit = "secgate/impacket_test.go: impacketTargets parses the [domain/]user[:password]@host operand so the host reaches the scope check, takes the host after the LAST @ so a password containing @ cannot shift it, and discards the values that read as hosts but are not (a -hashes LM:NT pair parses as host:port, an -outputfile name parses as a hostname); an operand with no usable host fails closed. ntlmrelayx.py must name one -t target, and -tf is denied because it reads targets from a file the scope check never sees. fileaccess confines -outputfile to the scratch directory. Exploit tier, so the phase forces per-action confirmation"

// auditStatus returns the recorded audit for a binary and whether it is
// complete. An impacket entry point shares one audit note.
func auditStatus(binary string) (note string, audited bool) {
	if note, ok := auditedBinaries[binary]; ok {
		return note, true
	}
	if note, ok := pendingAudits[binary]; ok {
		return note, false
	}
	if t, ok := toolFor(binary); ok && t.Package == "py3-impacket" {
		return impacketAudit, true
	}
	return "", false
}

// externalEngageAllowlist is the EXTERNAL-profile allowlist: every audited
// catalog binary that addresses a network destination, of either tier.
//
// This list is the gate's reachability control, not its autonomy control. A
// binary missing from it cannot run at all, so an exploit-tier tool belongs on
// it; what keeps that tool from running unattended is the exploit and post-ex
// phase forcing per-action confirmation whatever the mode, the operator's
// allowed_binaries bound, and the per-finding catalog in exploitallow.go.
// Conflating the two controls would leave every exploit tool unreachable rather
// than merely attended.
//
// A reachLocal binary is never on it: the external profile denies a command with
// no verifiable target, and keeping read utilities off the list closes the
// file-disclosure path where an in-scope host operand passes the scope check
// while a file operand is read.
func externalEngageAllowlist() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Reach != reachExternal {
			continue
		}
		if _, audited := auditStatus(t.Binary); audited {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}
