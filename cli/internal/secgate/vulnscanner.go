package secgate

import "strings"

// vulnscanner.go audits osv-scanner and grype: each reads a local path and prints a report, so it addresses no host and the gate admits it with no scope target.

// vulnScannerBinaries are the scanners this file audits.
var vulnScannerBinaries = map[string]bool{"osv-scanner": true, "grype": true, "trivy": true}

// osvDeniedFlags maps an osv-scanner flag to why it is denied.
var osvDeniedFlags = map[string]string{
	"call-analysis":                   "runs the scanned project's build scripts",
	"config":                          "replaces the configuration, including the ignore list and the data source",
	"serve":                           "starts an HTTP listener for the report",
	"port":                            "binds the report listener to a port",
	"data-source":                     "names a metadata host the scope check never reads",
	"maven-registry":                  "names a registry host the scope check never reads",
	"download-offline-databases":      "fetches a database from a host the scope check never reads",
	"experimental-plugins":            "selects which extractors run over the scanned tree",
	"experimental-no-default-plugins": "selects which extractors run over the scanned tree",
	"experimental-mcp":                "runs osv-scanner as a service rather than a scan",
}

// osvDeniedSubcommands maps a first non-flag token to why it is denied.
var osvDeniedSubcommands = map[string]string{
	"fix":              "rewrites the manifest and lockfile under scan",
	"update":           "rewrites the manifest under scan",
	"experimental-mcp": "runs osv-scanner as a service rather than a scan",
}

// osvScanImageRemote reports whether the argv is scan image without --archive, which resolves against a registry.
func osvScanImageRemote(args []string) bool {
	var words []string
	for _, a := range args {
		if a == "" || a[0] == '-' {
			continue
		}
		words = append(words, strings.ToLower(a))
	}
	if len(words) < 2 || words[0] != "scan" || words[1] != "image" {
		return false
	}
	return !hasAnyFlag(args, "--archive")
}

// grypeDeniedFlags maps a grype flag to why it is denied.
var grypeDeniedFlags = map[string]string{
	"template": "renders a Go template read from a file",
	"t":        "renders a Go template read from a file",
	"config":   "loads a configuration that sets every other option",
	"c":        "loads a configuration that sets every other option",
	"profile":  "loads a configuration profile that sets every other option",
}

// grypeRemoteSchemes are the source prefixes that resolve the operand against a remote registry.
var grypeRemoteSchemes = []string{"registry:", "docker:", "podman:", "oci-registry:"}

// grypeDeniedSubcommands maps a grype subcommand to why it is denied.
var grypeDeniedSubcommands = map[string]string{
	"db":     "downloads or deletes the vulnerability database",
	"config": "writes a configuration a later run would load",
}

// flagName renders a dash-led argument's name without its dashes or value, and "" for a non-flag argument.
func flagName(a string) string {
	if len(a) < 2 || a[0] != '-' {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
	return name
}

// vulnScannerViolation denies the osv-scanner and grype forms the gate cannot bound.
func vulnScannerViolation(name string, args []string) (Decision, bool) {
	switch name {
	case "osv-scanner":
		for _, a := range args {
			if why, denied := osvDeniedFlags[flagName(a)]; denied {
				return Decision{
					Allowed:    false,
					Reason:     "osv-scanner " + a + " " + why,
					Suggestion: "scan a path with --format json and read the report from stdout",
				}, true
			}
		}
		for _, a := range args {
			if a == "" || a[0] == '-' {
				continue
			}
			if why, denied := osvDeniedSubcommands[strings.ToLower(a)]; denied {
				return Decision{
					Allowed:    false,
					Reason:     "osv-scanner " + a + " " + why,
					Suggestion: "use osv-scanner scan source, which only reports",
				}, true
			}
			break
		}
		if osvScanImageRemote(args) {
			return Decision{
				Allowed:    false,
				Reason:     "osv-scanner scan image resolves the operand against a container registry the scope check never reads",
				Suggestion: "export the image to a tar and scan it with --archive",
			}, true
		}
		if a, bad := osvEscapingOperand(args); bad {
			return Decision{
				Allowed:    false,
				Reason:     "osv-scanner operand " + a + " is outside the scratch working directory",
				Suggestion: "scan a path the executor staged, e.g. osv-scanner scan source -r .",
			}, true
		}
	case "grype":
		for _, a := range args {
			if why, denied := grypeDeniedFlags[flagName(a)]; denied {
				return Decision{
					Allowed:    false,
					Reason:     "grype " + a + " " + why,
					Suggestion: "use -o json and read the report from stdout",
				}, true
			}
		}
		for _, a := range args {
			if a == "" || a[0] == '-' {
				continue
			}
			if why, denied := grypeDeniedSubcommands[strings.ToLower(a)]; denied {
				return Decision{
					Allowed:    false,
					Reason:     "grype " + a + " " + why,
					Suggestion: "scan a local source, e.g. grype dir:. -o json",
				}, true
			}
			break
		}
		for _, a := range args {
			if a == "" || a[0] == '-' {
				continue
			}
			lower := strings.ToLower(a)
			for _, scheme := range grypeRemoteSchemes {
				if strings.HasPrefix(lower, scheme) {
					return Decision{
						Allowed:    false,
						Reason:     "grype " + a + " resolves the operand against a remote registry the scope check never reads",
						Suggestion: "scan a local source, e.g. dir:, file:, sbom: or oci-archive:",
					}, true
				}
			}
		}
		// Without a scheme grype tries the filesystem and then a registry, so the destination depends on what exists.
		if a, bad := grypeSchemelessOperand(args); bad {
			return Decision{
				Allowed:    false,
				Reason:     "grype " + a + " names no source scheme, so whether it reads a path or a registry depends on what exists",
				Suggestion: "give the source explicitly, e.g. dir:" + a + " or oci-archive:" + a,
			}, true
		}
		if a, bad := grypeEscapingOperand(args); bad {
			return Decision{
				Allowed:    false,
				Reason:     "grype operand " + a + " is outside the scratch working directory",
				Suggestion: "scan a path the executor staged, e.g. grype dir:. -o json",
			}, true
		}
	}
	return Decision{}, false
}

// grypeLocalSchemes are source prefixes that cannot select a remote registry.
var grypeLocalSchemes = []string{
	"dir:", "file:", "sbom:", "oci-archive:", "docker-archive:", "singularity:", "purl:", "cpe:",
}

// grypeArgLetters are the grype short flags that take a value.
const grypeArgLetters = "ocfst"

// grypeSchemelessOperand reports the first non-flag token that names no source scheme, skipping a flag's value.
func grypeSchemelessOperand(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a[0] == '-' {
			if n := flagName(a); n != "" && !strings.Contains(a, "=") && grypeFlagTakesValue(a, n) {
				i++
			}
			continue
		}
		lower := strings.ToLower(a)
		for _, scheme := range grypeLocalSchemes {
			if strings.HasPrefix(lower, scheme) {
				return "", false
			}
		}
		return a, true
	}
	return "", false
}

// grypeValueLongs are the grype long flags that take a value.
var grypeValueLongs = map[string]bool{
	"output": true, "file": true, "fail-on": true, "scope": true,
	"distro": true, "platform": true, "name": true, "exclude": true,
	"sort-by": true, "ignore-states": true, "vex": true,
	"config": true, "profile": true, "template": true,
}

// grypeFlagTakesValue reports whether a dash-led argument consumes the next one.
func grypeFlagTakesValue(a, name string) bool {
	if strings.HasPrefix(a, "--") {
		return grypeValueLongs[name]
	}
	return len(name) == 1 && strings.ContainsAny(name, grypeArgLetters)
}

// osvValueLongs are the osv-scanner long flags that take a value.
var osvValueLongs = map[string]bool{
	"lockfile": true, "sbom": true, "format": true, "output": true,
	"output-file": true, "verbosity": true, "config": true, "port": true,
	"data-source": true, "maven-registry": true, "call-analysis": true,
	"no-call-analysis": true, "licenses": true, "manifest": true,
	"archive":              true,
	"experimental-exclude": true, "experimental-plugins": true,
	"experimental-disable-plugins": true, "upgrade-config": true,
	"ignore-vulns": true,
}

// osvSubcommands are the tokens that select a command rather than name a path.
var osvSubcommands = map[string]bool{
	"scan": true, "source": true, "image": true, "fix": true, "update": true,
}

// osvEscapingOperand reports the first positional scan path that leaves the scratch working directory.
func osvEscapingOperand(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a[0] == '-' {
			if n := flagName(a); n != "" && !strings.Contains(a, "=") && osvFlagTakesValue(a, n) {
				i++
			}
			continue
		}
		if osvSubcommands[strings.ToLower(a)] {
			continue
		}
		if pathEscapesScratch(a) {
			return a, true
		}
	}
	return "", false
}

// osvFlagTakesValue reports whether a dash-led osv-scanner argument consumes the next one.
func osvFlagTakesValue(a, name string) bool {
	if strings.HasPrefix(a, "--") {
		return osvValueLongs[name]
	}
	return len(name) == 1 && strings.ContainsAny(name, "LSfo")
}

// grypeEscapingOperand reports the first source operand whose path, after its scheme, leaves the scratch directory.
func grypeEscapingOperand(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a[0] == '-' {
			if n := flagName(a); n != "" && !strings.Contains(a, "=") && grypeFlagTakesValue(a, n) {
				i++
			}
			continue
		}
		lower := strings.ToLower(a)
		for _, scheme := range grypeLocalSchemes {
			if !strings.HasPrefix(lower, scheme) {
				continue
			}
			if scheme == "cpe:" {
				return "", false
			}
			if path := a[len(scheme):]; pathEscapesScratch(path) {
				return a, true
			}
			return "", false
		}
	}
	return "", false
}
