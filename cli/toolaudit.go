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
}

// pendingAudits are catalog binaries that are present in the image but not yet
// on the EXTERNAL allowlist, with what each audit must still cover. A persona
// may not name one, which TestPersonaPromptsAvoidUnauditedTools enforces.
var pendingAudits = map[string]string{
	"masscan": "needs a normalizing flag matcher: masscan lowercases its flag names and strips - and _, so --excludefile, --exclude-file and --EXCLUDEFILE are one flag and a literal denylist misses two of them. Until then its config and target-file flags (-c/--conf, --excludefile, -iL, --resume) are unbounded. Separately, the scope extractor denies a CIDR argument outright, so masscan's range form cannot be authorized at all and the tool has no advantage over nmap",
	"kinit":   "the destination is a KDC resolved from the realm through DNS and krb5.conf, so the scope check cannot see it, and a principal of the form user@REALM makes the extractor scope-check the realm as if it were a host. Needs either a realm-aware extractor rule or the execution-location work, with the worker firewall as the enforcing layer meanwhile",
	"aws":     "exploit tier, so never unattended; still needs --endpoint-url scope-checked, --cli-input-json/--cli-input-yaml denied as config indirection, and the mutating operations enumerated",
	"kubectl": "exploit tier, so never unattended; still needs exec/run/attach/cp/port-forward/proxy/debug denied, --kubeconfig denied, and --server/-s scope-checked",
	"socat":   "exploit tier, so never unattended; still needs an address-spec parser that permits only TCP, TCP4, TCP6, OPENSSL, UDP and STDIO, denies EXEC/SYSTEM/SHELL/PTY and OPEN/CREATE/GOPEN, extracts the host from each permitted spec, and fails closed on an unparsable spec",
}

// impacketAudit is the audit every impacket entry point shares. Its target form
// carries a credential, which must be stripped before the command signature
// reaches the action transcript or the transcript leaks the password.
const impacketAudit = "exploit tier, so never unattended; still needs the domain/user:pass@host target form parsed so the host is scope-checked and the credential segment is stripped from the recorded signature, -outputfile confined to scratch, and ntlmrelayx.py -c denied"

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
		return impacketAudit, false
	}
	return "", false
}

// externalEngageAllowlist is the EXTERNAL-profile allowlist: the catalog's
// tierEnum binaries that address a network destination and whose flag surface
// has been audited. A tierExploit binary is never on it, so it cannot run
// unattended; it reaches execution only through the armed,
// per-action-confirmed exploit tier. A reachLocal binary is never on it either:
// the external profile denies a command with no verifiable target, and keeping
// read utilities off the list closes the file-disclosure path.
func externalEngageAllowlist() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Tier != tierEnum || t.Reach != reachExternal {
			continue
		}
		if _, audited := auditStatus(t.Binary); audited {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}
