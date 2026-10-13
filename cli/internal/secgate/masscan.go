package secgate

import "strings"

func masscanDenied(c Command) (Decision, bool) {
	if !strings.EqualFold(baseName(c.Binary), "masscan") {
		return Decision{}, false
	}
	return Decision{Reason: "masscan raw Ethernet bypasses the worker destination guard"}, true
}
