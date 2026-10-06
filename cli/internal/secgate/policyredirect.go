package secgate

import "strings"

func policyRedirectViolation(c Command) bool {
	switch strings.ToLower(baseName(c.Binary)) {
	case "wget":
		return true
	case "curl":
		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "--") {
				name, _, _ := strings.Cut(arg, "=")
				switch name {
				case "--location", "--location-trusted", "--follow", "--follow-all", "--config":
					return true
				}
				continue
			}
			if !strings.HasPrefix(arg, "-") || len(arg) < 2 {
				continue
			}
			for i := 1; i < len(arg); i++ {
				if arg[i] == 'L' || arg[i] == 'K' {
					return true
				}
				if strings.ContainsRune(shortArgLetters["curl"], rune(arg[i])) {
					break
				}
			}
		}
	}
	return false
}
