package secgate

import "testing"

func TestMasscanRawEthernetIsDeniedOnEveryGatePath(t *testing.T) {
	for _, classify := range []func(Command) Decision{Classify, ClassifyExternalConfirmed, ClassifyLocal, ClassifyLocalConfirmed} {
		c := Command{Binary: "masscan", Args: []string{"-p", "8080", "--rate", "10", "192.0.2.10"}}
		if d := classify(c); d.Allowed {
			t.Fatal("masscan reached the worker despite bypassing its address guard")
		}
	}
}
