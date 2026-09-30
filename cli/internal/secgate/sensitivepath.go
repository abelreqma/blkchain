package secgate

import (
	"os"
	"path/filepath"
	"strings"
)

func SensitivePathViolation(c Command, protected []string, scratch string) (arg string, bad bool) {
	sep := string(os.PathSeparator)
	for _, tok := range c.Args {
		if tok == "" {
			continue
		}
		for _, cand := range sensitiveCandidates(tok) {
			if cand == "" {
				continue
			}
			// A .env reference is denied whatever it resolves to.
			if filepath.Base(cand) == ".env" {
				return tok, true
			}

			if scratch == "" && cand == tok && !filepath.IsAbs(cand) && strings.Contains(cand, "..") {
				// Fail closed for the whole-token candidate only (the new
				// sub-candidates are not extended into this fallback): the
				// protected paths cannot be resolved without a scratch dir, so
				// compare the cleaned base name against the protected file base
				// names instead of over-denying every arg.
				b := filepath.Base(filepath.Clean(cand))
				for _, p := range protected {
					if b == filepath.Base(filepath.Clean(p)) {
						return tok, true
					}
				}
				continue
			}

			var resolved string
			if filepath.IsAbs(cand) {
				resolved = filepath.Clean(cand)
			} else if scratch != "" {
				resolved = filepath.Clean(filepath.Join(scratch, cand))
			} else {
				continue
			}
			if filepath.Base(resolved) == ".env" {
				return tok, true
			}
			for _, p := range protected {
				cp := filepath.Clean(p)
				if resolved == cp || strings.HasPrefix(resolved, cp+sep) {
					return tok, true
				}
			}
		}
	}
	return "", false
}

// sensitiveCandidates derives the path strings to test from one argument token:
// the whole token, the substring after the last '=' (so --output=PATH and
// KEY=@PATH are reached), and, for a single-dash token containing '/', the
// substring from the first '/' (so -oPATH is reached). A single leading '@' (a
// data-flag @file reference) is stripped from the whole token and from the '='
// value. Extraction never denies on its own: a mis-extracted fragment that
// resolves to no protected path and is not a .env file has zero effect, because
// the caller denies only on a resolved-protected or .env match.
func sensitiveCandidates(tok string) []string {
	cands := []string{tok}
	if s := strings.TrimPrefix(tok, "@"); s != tok {
		cands = append(cands, s)
	}
	if i := strings.LastIndexByte(tok, '='); i >= 0 {
		cands = append(cands, strings.TrimPrefix(tok[i+1:], "@"))
	}
	if strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") {
		if i := strings.IndexByte(tok, '/'); i >= 0 {
			cands = append(cands, tok[i:])
		}
	}
	return cands
}
