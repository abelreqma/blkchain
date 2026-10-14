package secgate

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

func ikeScanViolation(name string, args []string) (Decision, bool) {
	if name != "ike-scan" {
		return Decision{}, false
	}
	if err := validIKEScan(args); err != nil {
		return Decision{Reason: "ike-scan " + err.Error()}, true
	}
	return Decision{}, false
}

func validIKEScan(args []string) error {
	ikev2, noDNS, source, retry, timeout, natT := false, false, false, false, false, false
	target := ""
	for _, arg := range args {
		switch {
		case arg == "--ikev2" && !ikev2:
			ikev2 = true
		case arg == "--nodns" && !noDNS:
			noDNS = true
		case arg == "--nat-t" && !natT:
			natT = true
		case arg == "--sport=0" && !source:
			source = true
		case strings.HasPrefix(arg, "--retry=") && !retry:
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--retry="))
			if err != nil || n < 1 || n > 3 {
				return errors.New("retry must be 1-3")
			}
			retry = true
		case strings.HasPrefix(arg, "--timeout=") && !timeout:
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--timeout="))
			if err != nil || n < 250 || n > 2000 {
				return errors.New("timeout must be 250-2000 ms")
			}
			timeout = true
		case !strings.HasPrefix(arg, "-") && target == "" && net.ParseIP(arg).To4() != nil:
			target = arg
		default:
			return errors.New("requires one literal IP and audited IKEv2 options")
		}
	}
	if !ikev2 || !noDNS || !source || !retry || !timeout || target == "" {
		return errors.New("requires --ikev2 --nodns --sport=0 --retry=1-3 --timeout=250-2000 and one IP")
	}
	return nil
}
