package secgate

import "strings"

// writeFlags maps a binary base name to the flags whose value is a file path
// the tool writes, or (wget --post-file, --body-file) reads and sends. Every
// such value must stay inside the scratch working directory.
var writeFlags = map[string][]string{
	"curl": {
		"-o", "--output", "-T", "--upload-file", "-D", "--dump-header",
		"-c", "--cookie-jar", "--output-dir", "--trace", "--trace-ascii",
		"--stderr", "--libcurl", "--etag-save", "--hsts", "--alt-svc",
	},
	"wget": {
		"-O", "--output-document", "-o", "--output-file", "-a", "--append-output",
		"-P", "--directory-prefix", "--save-cookies", "--warc-file",
		"--rejected-log", "--post-file", "--body-file", "--hsts-file",
	},
	"ss":   {"-D", "--diag"},
	"nc":   {"-o"},
	"ncat": {"-o", "--output", "-x", "--hex-dump"},
	"nmap": {"-oN", "-oX", "-oG", "-oA", "-oS", "-oJ", "--stylesheet", "--resume"},
	// dnsrecon: -x/-c/-j/--db write result files. -D/--dictionary and
	// -iL/--input-list read a file whose lines become DNS queries (a read and
	// exfiltrate primitive). argparse also accepts -i as an abbreviation of -iL.
	"dnsrecon": {
		"-x", "--xml", "-c", "--csv", "-j", "--json", "--db",
		"-D", "--dictionary", "-iL", "--input-list", "-i",
	},
	// smbclient and rpcclient: -l/--log-basename writes log files. nbtscan -O
	// writes a log file. Their exec, config, credential, and file-target flags
	// are denied outright by Classify.
	"smbclient": {"-l", "--log-basename"},
	"rpcclient": {"-l", "--log-basename"},
	"nbtscan":   {"-O"},
	// ldapsearch: -f reads the operations from a file, -T names the directory
	// that -t writes into (-t itself is denied by Classify).
	"ldapsearch": {"-f", "-T"},
	// onesixtyone: -c reads the community strings from a file and sends them to
	// the target, -o writes a log. -i (targets from a file) is denied by Classify.
	"onesixtyone": {"-c", "-o"},
	// gobuster: -o writes; -w, -p, and -X read files whose lines are sent to the
	// target; the client certificate files are read for TLS.
	"gobuster": {
		"-o", "--output", "-w", "--wordlist", "-p", "--pattern",
		"-X", "--extensions-file", "--client-cert-file", "--client-cert-key",
		"--client-cert-pfx",
	},
	// ffuf: -o, -od, -of, and -debug-log write; -w, -cc, -ck, and -scraperfile
	// read. -config and -request are denied outright (denyFlags).
	"ffuf": {"-o", "-od", "-of", "-debug-log", "-w", "-cc", "-ck", "-scraperfile"},
	// nikto: -o/-output and -Save write; -key and -RSAcert read certificate files.
	"nikto": {"-o", "-output", "-Save", "-key", "-RSAcert"},
	// tcpdump: -w writes the capture, -r reads one back, -F reads the filter
	// expression from a file. -c is a packet count, not a path.
	"tcpdump": {"-w", "-r", "-F"},
	// sslscan: --xml writes the report; the certificate and key flags read files.
	"sslscan": {"--xml", "--certs", "--pk", "--ca-certs"},
	// jq: -f reads the filter program, and a parse error echoes the offending
	// line, so an arbitrary path is a read primitive.
	"jq": {"-f", "--from-file"},
	// john: --pot and --session write, --wordlist and --loopback read a file
	// whose lines become candidates.
	"john": {"--pot", "--session", "--wordlist", "--loopback"},
	// openssl: -out and -keyout write, and the input, certificate, and key flags
	// read files.
	"openssl": {"-out", "-keyout", "-in", "-cert", "-key", "-CAfile", "-CApath", "-writerand", "-rand"},
	// file: -C compiles a magic file and -m loads one.
	"file": {"-C", "--compile", "-m", "--magic-file"},
	// kinit writes a credential cache and reads a keytab; klist reads both.
	"kinit": {"-c", "-t"},
	"klist": {"-c", "-k"},
	// kubectl reads the client certificate, key, and CA from these paths.
	"kubectl": {"--client-certificate", "--client-key", "--certificate-authority", "--cache-dir"},
	// aws writes through --outfile and reads a CA bundle; its cli-input flags are
	// denied outright because they supply every other parameter from a file.
	"aws": {"--outfile", "--ca-bundle"},
}

// dataFlags maps a binary base name to the flags whose value may carry an
// `@file` reference (the tool reads that file and sends or prints it).
// --data-raw is deliberately excluded: curl gives a leading '@' no special
// meaning there, so its value is never a file path.
var dataFlags = map[string][]string{
	"curl": {
		"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode",
		"-F", "--form", "--json", "-w", "--write-out", "--variable",
	},
}

// denyFlags maps a binary base name to flags denied outright, whatever their
// value. Each one hands control to a file (a config file that can itself set
// output=, url=, or data=) or a command, so the arg layer cannot validate what
// it will do.
var denyFlags = map[string][]string{
	"curl": {"-K", "--config"},
	"wget": {"--config", "-e", "--execute", "--use-askpass"},
	// john --config loads a configuration that can itself select an external
	// mode, which is compiled code john runs.
	"john": {"--config"},
	// openssl -config loads a configuration file that sets any other option.
	"openssl": {"-config"},
	// file -f reads the list of paths to inspect from a file, so the paths never
	// reach the argument layer.
	"file": {"-f", "--files-from"},
	// aws --cli-input-json and --cli-input-yaml supply every parameter of the
	// operation from a file, including the endpoint the scope check reads.
	"aws": {"--cli-input-json", "--cli-input-yaml"},
	// jq --rawfile and --slurpfile take a variable name and then a path, so the
	// bound would check the name and let the path through. The executor pipes
	// JSON in as a pipeline stage, so neither flag is needed.
	"jq": {"--rawfile", "--slurpfile"},
	// kubectl --kubeconfig loads a file that sets the server, the credentials,
	// and an exec credential plugin, which runs a binary of its choosing. The
	// server must be named on the command line where the scope check sees it.
	"kubectl": {"--kubeconfig"},
	// ffuf -config loads options from a file; -request reads a raw request file
	// whose Host header is the target, which the scope check never sees.
	"ffuf": {"-config", "-request"},
}

// goFlagBins lists binaries that parse options with Go's flag package (ffuf) or
// Getopt::Long (nikto), where --name and -name are the same option, so `--o`
// reaches -o.
var goFlagBins = map[string]bool{"ffuf": true, "nikto": true}

// shortArgLetters lists, per binary, the single-letter short flags that take
// an argument. It is needed to parse bundles such as `curl -so ../x`, where
// the first arg-taking letter consumes the rest of the bundle (or the next
// argument) as its value.
var shortArgLetters = map[string]string{
	"curl": "AbcCdDeEFHKmoPQrtTuUwxXyYz",
	"wget": "aABDeoOPQtTwilIRXUFH",
	"ss":   "DFNA",
	"nc":   "oeciIpPqsTVwWxXm",
	"ncat": "oxeciIpPqsTVwWXm",
	// dnsrecon (argparse): -d -r -n -D -t -c -j -x -i take a value.
	"dnsrecon": "drnDtcjxi",
	// smbclient/rpcclient (popt): the value-taking short options.
	"smbclient": smbArgLetters + "cTAs",
	"rpcclient": smbArgLetters + "cTAs",
	"nbtscan":   "fstbmpO",
	// ldapsearch (getopt) and onesixtyone (getopt): the value-taking letters.
	"ldapsearch":  ldapArgLetters,
	"onesixtyone": "ciow",
	// gobuster (pflag): only letters that take a value in every mode. -c, -d,
	// and -r are booleans in some modes, and leaving them out errs toward denial.
	"gobuster": "opwtaHmPUuxXsbB",
	// tcpdump (getopt): the value-taking letters, shared with the classifier so
	// one bundle is parsed the same way by both layers.
	"tcpdump": tcpdumpArgLetters,
	// file (getopt): -m and -f take a value.
	"file": "mf",
	// kinit and klist (getopt): the value-taking letters.
	"kinit": "clrpStk",
	"klist": "cke",
	// jq: -f takes the filter file.
	"jq": "f",
}

// abbrevMin lists binaries whose long options accept unambiguous prefixes
// (getopt_long, argparse), so `--dir=/x` means --directory-prefix. The value is
// the shortest matched argument length, dashes included. wget needs three
// letters after the dashes. argparse accepts a single letter, so `--j` and
// `--x` reach dnsrecon's --json and --xml.
var abbrevMin = map[string]int{"wget": 5, "dnsrecon": 3, "smbclient": 3, "rpcclient": 3}

// configOptionNote is the reason attached to an outright-denied flag.
const configOptionNote = " (option not permitted: unvalidatable config or command indirection)"

// FileAccessViolation reports the first argument that references a file path
// outside run_command's scratch working directory, or that hands control to an
// unvalidatable config file. It returns bad=true with the offending value (or
// the denied flag, with a reason) when:
//   - a WRITE/OUTPUT flag (or wget --post-file/--body-file) has a value that is
//     an absolute path or has a ".." segment;
//   - a curl DATA-SEND flag carries an `@file` reference (or a form `=<file`)
//     that is absolute or has a ".." segment;
//   - a config or command indirection flag (curl -K/--config; wget --config,
//     -e/--execute, --use-askpass) appears at all, even with a relative path.
//
// run_command's cwd is a throwaway scratch dir outside the engagement
// workspace, so relative paths without ".." stay in it. Anything escaping it is
// an attempt to overwrite the audit log or store, or to read and exfiltrate a
// file.
//
// Coverage: this is a per-flag policy for the default-allowlist binaries only
// (curl, wget, nmap, ss, nc, ncat, dnsrecon, smbclient, rpcclient, nbtscan,
// ldapsearch, onesixtyone, gobuster, ffuf, nikto). host, nslookup, showmount,
// snmpwalk, and dig have no bounded file flag (the file and credential options
// of snmpwalk and dig are denied by Classify), so they need no entry. Binaries an operator adds with an
// `allow` line are NOT covered and must be reviewed for their own write, data,
// and config flags before being allowed. Input-only read flags of other tools
// (-w/--wordlist, -iL, -i/--input-file) are not restricted: reading a wordlist
// or input list is a legitimate, low-risk operation. dnsrecon is the exception:
// its -D/--dictionary and -iL/--input-list turn file lines into DNS queries, so
// they are bounded like a write flag. Code-execution flags (nmap --script and
// --datadir, nc/ncat -e, ip netns) are denied separately by Classify.
func FileAccessViolation(c Command) (arg string, bad bool) {
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	args := c.Args

	for i := range args {
		if f, _, ok := flagOccurrence(name, args, i, denyFlags[name]); ok {
			return f + configOptionNote, true
		}
		if _, v, ok := flagOccurrence(name, args, i, writeFlags[name]); ok && pathEscapesScratch(v) {
			return v, true
		}
		if f, v, ok := flagOccurrence(name, args, i, dataFlags[name]); ok {
			if p, isFile := refPath(f, v); isFile && pathEscapesScratch(p) {
				return v, true
			}
		}
	}
	return "", false
}

// flagOccurrence reports whether args[i] is an occurrence of one of flags and
// returns the matched flag and its value. It handles the separate-argument form
// (`-o file`, `--output file`), `--flag=value` (and `-oN=value`), a short flag
// glued to its value (`-ofile`), a short flag inside a bundle (`-so file`), and,
// for binaries in abbrevBins, an abbreviated long flag. A flag with no
// following value matches with an empty value.
func flagOccurrence(name string, args []string, i int, flags []string) (flag, value string, ok bool) {
	if len(flags) == 0 {
		return "", "", false
	}
	a := args[i]
	if !strings.HasPrefix(a, "-") {
		return "", "", false
	}
	if goFlagBins[name] && strings.HasPrefix(a, "--") {
		a = a[1:]
	}
	next := func() string {
		if i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	n, v, hasEq := strings.Cut(a, "=")
	if strings.HasPrefix(a, "--") {
		for _, f := range flags {
			long := strings.HasPrefix(f, "--")
			// nmap uses getopt_long_only, so a multi-char single-dash flag such
			// as -oN is also accepted as --oN.
			if !long && len(f) > 2 && n == "-"+f {
				if hasEq {
					return f, v, true
				}
				return f, next(), true
			}
			if !long {
				continue
			}
			if n == f || (abbrevMin[name] > 0 && len(n) >= abbrevMin[name] && strings.HasPrefix(f, n)) {
				if hasEq {
					return f, v, true
				}
				return f, next(), true
			}
		}
		return "", "", false
	}
	for _, f := range flags {
		if strings.HasPrefix(f, "--") {
			continue
		}
		if n == f {
			if hasEq {
				return f, v, true
			}
			return f, next(), true
		}
		// A multi-char single-dash flag glued to its value (-oNfile).
		if len(f) > 2 && strings.HasPrefix(a, f) {
			return f, a[len(f):], true
		}
	}
	letters := shortArgLetters[name]
	if letters == "" {
		return "", "", false
	}
	for j := 1; j < len(a); j++ {
		if !strings.ContainsRune(letters, rune(a[j])) {
			continue
		}
		f := "-" + string(a[j])
		val := a[j+1:]
		if val == "" {
			val = next()
		}
		for _, ff := range flags {
			if ff == f {
				return f, val, true
			}
		}
		return "", "", false // an arg-taking letter that is not ours ate the rest
	}
	return "", "", false
}

// refPath extracts the file path from a data-flag value, or ok=false when the
// value is plain literal data. Every flag accepts `@path` and `name=@path`.
// --data-urlencode and --variable also accept `name@path`, and -F/--form also
// accept `name=<path` and `<path` (curl reads the file content).
func refPath(flag, value string) (path string, ok bool) {
	if strings.HasPrefix(value, "@") {
		return value[1:], true
	}
	if idx := strings.Index(value, "=@"); idx >= 0 {
		return value[idx+2:], true
	}
	switch flag {
	case "--data-urlencode", "--variable":
		at, eq := strings.IndexByte(value, '@'), strings.IndexByte(value, '=')
		if at >= 0 && (eq < 0 || at < eq) {
			return value[at+1:], true
		}
	case "-F", "--form":
		if strings.HasPrefix(value, "<") {
			return value[1:], true
		}
		if idx := strings.Index(value, "=<"); idx >= 0 {
			return value[idx+2:], true
		}
	}
	return "", false
}

// pathEscapesScratch reports whether p is an absolute path or has a ".."
// path segment, either of which would let it reach outside the scratch
// working directory that run_command's cmd.Dir confines relative paths to.
func pathEscapesScratch(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}
