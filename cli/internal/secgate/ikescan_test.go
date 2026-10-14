package secgate

import "testing"

func TestIKEScanBoundedForms(t *testing.T) {
	base := []string{"--ikev2", "--nodns", "--sport=0", "--retry=2", "--timeout=1000", "192.0.2.10"}
	for _, args := range [][]string{
		base,
		{"--nat-t", "--ikev2", "--nodns", "--sport=0", "--retry=3", "--timeout=2000", "192.0.2.10"},
	} {
		if d := Classify(Command{Binary: "ike-scan", Args: args}); !d.Allowed {
			t.Errorf("bounded scan %v denied: %s", args, d.Reason)
		}
	}
	for _, args := range [][]string{
		{"--ikev2", "--nat-t", "192.0.2.10"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=4", "--timeout=1000", "192.0.2.10"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=2001", "192.0.2.10"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "192.0.2.10", "192.0.2.11"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "192.0.2.0/24"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "--sourceip=192.0.2.11", "192.0.2.10"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "--dport=4500", "192.0.2.10"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "--file=targets.txt"},
		{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "2001:db8::10"},
	} {
		c := Command{Binary: "ike-scan", Args: args}
		if d := Classify(c); d.Allowed {
			t.Errorf("unsafe scan %v allowed", args)
		}
		if d := ClassifyExternalConfirmed(c); d.Allowed {
			t.Errorf("confirmed unsafe scan %v allowed", args)
		}
		if d := ClassifyLocalConfirmed(c); d.Allowed {
			t.Errorf("local unsafe scan %v allowed", args)
		}
	}
}
