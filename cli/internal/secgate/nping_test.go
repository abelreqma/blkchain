package secgate

import (
	"strings"
	"testing"
)

func TestNpingPayloadIsDataNotAnotherTarget(t *testing.T) {
	c := Command{Binary: "nping", Args: []string{"--udp", "--data", "0x00000000aabb", "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"}}
	targets, ok := ExtractTargets(c)
	if !ok || len(targets) != 1 || targets[0] != "192.0.2.10" {
		t.Fatalf("payload targets = %v, ok=%t", targets, ok)
	}
	scope, err := ParseScope(strings.NewReader("192.0.2.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ip, denied := ScopeViolation(scope, c); denied {
		t.Fatalf("payload bytes treated as out-of-scope IP %s", ip)
	}
}

func TestNpingBoundedProbeForms(t *testing.T) {
	for _, args := range [][]string{
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "192.0.2.10"},
		{"--tcp", "--flags", "ack", "-c", "2", "--rate", "1", "-p", "443", "192.0.2.10"},
		{"--tcp-connect", "--source-port", "53", "-c", "1", "--rate", "1", "-p", "443", "192.0.2.10"},
		{"--udp", "-c", "2", "--rate", "1", "-p", "4500", "192.0.2.10"},
		{"--udp", "--data", "0x00000000aabb", "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"},
		{"--icmp", "-c", "2", "--rate", "1", "192.0.2.10"},
	} {
		if d := Classify(Command{Binary: "nping", Args: args}); !d.Allowed {
			t.Errorf("bounded nping %v denied: %s", args, d.Reason)
		}
	}
	oversized := []string{"--udp", "--data", "0x" + strings.Repeat("ab", 513), "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"}
	if d := Classify(Command{Binary: "nping", Args: oversized}); d.Allowed {
		t.Fatal("oversized UDP payload accepted")
	}
}

func TestNpingRejectsUnboundedAndHiddenRoutes(t *testing.T) {
	for _, args := range [][]string{
		{"--tcp", "--flags", "syn", "-p", "443", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "-p", "443", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "999", "--rate", "1", "-p", "443", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "999", "-p", "443", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "1-65535", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "192.0.2.0/24"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "192.0.2.10", "192.0.2.11"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "--data-file", "payload", "192.0.2.10"},
		{"--echo-server", "-c", "2", "--rate", "1", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "--interface", "eth0", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "--send-eth", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "-c", "2", "--rate", "1", "-p", "443", "--dest-ip", "192.0.2.11", "192.0.2.10"},
		{"--tcp-connect", "--source-port", "-1", "-c", "1", "--rate", "1", "-p", "443", "192.0.2.10"},
		{"--udp", "--data", "0x123", "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"},
		{"--udp", "--data-string", "payload", "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"},
		{"--tcp", "--flags", "syn", "--data", "0x1234", "-c", "1", "--rate", "1", "-p", "443", "192.0.2.10"},
	} {
		if d := Classify(Command{Binary: "nping", Args: args}); d.Allowed {
			t.Errorf("unsafe nping %v allowed", args)
		}
	}
}

func TestNpingBoundsHoldAfterHumanConfirmation(t *testing.T) {
	c := Command{Binary: "nping", Args: []string{"--tcp", "--flags", "syn", "-c", "999", "--rate", "1", "-p", "443", "192.0.2.10"}}
	for _, classify := range []func(Command) Decision{Classify, ClassifyExternalConfirmed, ClassifyLocal, ClassifyLocalConfirmed} {
		if d := classify(c); d.Allowed {
			t.Fatal("human confirmation bypassed the Nping packet bound")
		}
	}
}
