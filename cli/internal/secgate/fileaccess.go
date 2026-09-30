package secgate

import "strings"

// writeFlags maps a binary base name to the flags whose value is a
// WRITE/OUTPUT file path: the tool creates or overwrites that path.
var writeFlags = map[string][]string{
	"curl": {"-o", "--output", "-T", "--upload-file"},
	"wget": {"-O", "--output-document"},
	"nmap": {"-oN", "-oX", "-oG", "-oA", "-oS", "-oJ", "--stylesheet"},
}

// dataFlags maps a binary base name to the flags whose value may carry a
// curl `@file` data/form reference (the tool reads and sends that file).
// --data-raw is deliberately excluded: curl does not give a leading '@' any
// special meaning there, so its value is never a file path.
var dataFlags = map[string][]string{
	"curl": {"-d", "--data", "--data-binary", "--data-ascii", "-F", "--form"},
}

// FileAccessViolation reports the first argument that references a WRITE or
// DATA-SEND file path pointing outside run_command's scratch working
// directory: an absolute path, or a relative path with a ".." segment.
// run_command's cwd is a throwaway scratch dir with no secrets and nothing
// worth tampering with, so any path escaping it is either an attempt to
// overwrite something outside the sandbox (audit log, store, evidence) or to
// read and exfiltrate a file outside it via a data/form upload.
//
// Input-only read flags (-w/--wordlist, -iL, -i/--input-file) are not
// restricted: reading a wordlist or input list from outside the scratch dir
// is a legitimate, low-risk operation, not a tamper or exfil vector.
//
// arg is the offending flag value when bad is true.
func FileAccessViolation(c Command) (arg string, bad bool) {
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	args := c.Args

	for i := range args {
		if v, ok := flagValueAt(args, i, writeFlags[name]); ok && pathEscapesScratch(v) {
			return v, true
		}
	}
	for i := range args {
		v, ok := flagValueAt(args, i, dataFlags[name])
		if !ok {
			continue
		}
		if p, isFile := atFilePath(v); isFile && pathEscapesScratch(p) {
			return v, true
		}
	}
	return "", false
}

// flagValueAt returns the value belonging to a flag occurrence at args[i]:
// the next argument for an exact "-f value" match, or the suffix after '='
// for a "--flag=value" match. ok is false when args[i] matches none of flags,
// or an exact match has no following value.
func flagValueAt(args []string, i int, flags []string) (value string, ok bool) {
	if len(flags) == 0 {
		return "", false
	}
	a := args[i]
	for _, f := range flags {
		if a == f {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if strings.HasPrefix(f, "--") && strings.HasPrefix(a, f+"=") {
			return strings.TrimPrefix(a, f+"="), true
		}
	}
	return "", false
}

// atFilePath extracts the file path from a curl @file data/form value: a
// bare "@path" value, or a form field "name=@path". ok is false when value
// carries no @file reference (plain literal data).
func atFilePath(value string) (path string, ok bool) {
	if strings.HasPrefix(value, "@") {
		return value[1:], true
	}
	if idx := strings.Index(value, "=@"); idx >= 0 {
		return value[idx+2:], true
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
