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
	"smbclient":  "secgate/smbenum_test.go: execFlag denies -c/--command, smbDeny denies -T/-A/-s/--option/--use-krb5-ccache/--machine-pass, fileaccess bounds -l/--log-basename, enumGluedHostFlag denies a glued -I/-L/-M/-B",
	"rpcclient":  "secgate/smbenum_test.go: shares smbDeny with smbclient, execFlag denies -c/--command, enumGluedHostFlag denies a glued -I",
	"nbtscan":    "secgate/smbenum_test.go: enumConfigDeny denies -f/--file, which reads targets from a file the scope check never sees",
	"showmount":  "secgate/smbenum_test.go: no file, exec, or config flag; the target is positional and scope-checked",
	"ldapsearch": "secgate/netenum_test.go: enumConfigDeny denies -y/-h/-t/-C, fileaccess bounds -f/-T, the target must be an -H URI the scope check can read",
	"snmpwalk":   "secgate/netenum_test.go: enumConfigDeny denies -L/-M/-m with its value-taking letters accounted for",
	"ffuf":       "secgate/httpenum_test.go: execFlag denies -input-cmd/-input-shell, denyFlags denies -config/-request, writeFlags bounds -o/-od/-of/-w/-debug-log, targetFlagSpecs scope-checks -u/-x/-replay-proxy",
}

// pendingAudits are catalog binaries that are present in the image but not yet
// on the EXTERNAL allowlist, with the flag surface each audit must cover before
// it can be. A persona may name one of these only once it is audited, which
// TestPersonaPromptsNameOnlyAllowedTools enforces.
var pendingAudits = map[string]string{
	"masscan":    "deny -c/--conf and --excludefile, which read options and targets from a file; bound -oX/-oJ/-oL/--output-filename; require a -p/--ports and --rate bound; extract the target from the positional range, --range, and --exclude",
	"tcpdump":    "deny -z, which runs a command per rotated file; bound -w; bound -F and -r as data flags; require a -c packet bound",
	"sslscan":    "bound --xml and --show-certificate output paths; extract the target from the positional host:port and --sni",
	"openssl":    "deny -engine, which loads a shared object; bound -out/-keyout/-in; extract the target from s_client/s_time -connect and -proxy",
	"jq":         "bound -f/--from-file as config indirection; bound --slurpfile/--rawfile as data flags; no target channel",
	"socat":      "parse address specs: permit only TCP, TCP4, TCP6, OPENSSL, UDP and STDIO, deny EXEC/SYSTEM/SHELL/PTY and OPEN/CREATE/GOPEN, extract the host from each permitted spec, and fail closed on an unparsable spec",
	"kinit":      "no file flag beyond -t/-k keytab, which must be bounded; the KDC destination is resolved from the realm and is not visible to the extractor, so the worker firewall is the enforcing layer",
	"klist":      "bound -c/-k, which name a credential cache and a keytab; no target channel",
	"traceroute": "extract the target from the positional host; bound -i/-s; no file or exec flag in the busybox build",
	"file":       "deny -f/--files-from, which reads a list of paths the gate never sees; deny -C/-m, which compile and load a magic file; no target channel",
	"strings":    "no exec, write, or config flag; reads the named file only",
	"nm":         "deny --plugin, which loads a shared object; no write flag",
	"objdump":    "deny --plugin, which loads a shared object; no write flag",
	"readelf":    "no exec, write, or config flag; reads the named file only",
	"ldd":        "musl ldd is the dynamic loader and may run code from the inspected file; decide whether to deny it outright in favour of readelf -d",
	"getcap":     "no exec, write, or config flag; reads the named paths only",
	"id":         "no flag surface of concern; reads local identity only",
	"whoami":     "no flag surface of concern",
	"hostname":   "deny the setting form, which takes a name operand and changes host state",
	"uname":      "no flag surface of concern",
	"stat":       "bound the dereference flags; reads the named path only",
	"mount":      "deny every mounting form; only the no-operand listing is read-only",
	"ps":         "no flag surface of concern in the busybox build",
	"netstat":    "no flag surface of concern in the busybox build",
	"lsof":       "no flag surface of concern in the busybox build",
	"crontab":    "deny -e/-r and the file operand, which edit and remove crontabs; only -l is read-only",
	"sudo":       "permit exactly the listing argv (-l, -n -l, -ln, -nl) and nothing else; every operand and every other flag stays denied",
	"aws":        "exploit tier, so never unattended; still needs --endpoint-url scope-checked, --cli-input-json/--cli-input-yaml denied as config indirection, and the mutating operations enumerated",
	"kubectl":    "exploit tier, so never unattended; still needs exec/run/attach/cp/port-forward/proxy/debug denied, --kubeconfig denied, and --server/-s scope-checked",
	"gdb":        "exploit tier, so never unattended; still needs -x/--command/-ex/-p denied, which run code or attach to a process",
	"john":       "exploit tier, so never unattended; still needs --external denied, which runs compiled filter code, and its session and pot paths bounded",
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
// tierEnum binaries whose flag surface has been audited. A tierExploit binary is
// never on it, so it cannot run unattended; it reaches execution only through
// the armed, per-action-confirmed exploit tier.
func externalEngageAllowlist() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Tier != tierEnum {
			continue
		}
		if _, audited := auditStatus(t.Binary); audited {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}
