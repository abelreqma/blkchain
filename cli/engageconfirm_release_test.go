package main

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

type fakeReleaser struct{ released, restored int }

func (f *fakeReleaser) ReleaseTerminal() error { f.released++; return nil }
func (f *fakeReleaser) RestoreTerminal() error { f.restored++; return nil }

func rcCmd() secgate.Command {
	return secgate.Command{Binary: "nmap", Args: []string{"-F", "127.0.0.1"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork}
}

func TestPromptConfirmAnswers(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		allow    bool
		stop     bool
		edited   bool
		editArgs string
	}{
		{"allow", "y\n", true, false, false, ""},
		{"yes", "yes\n", true, false, false, ""},
		{"deny", "n\n", false, false, false, ""},
		{"empty denies", "\n", false, false, false, ""},
		{"garbage denies", "maybe\n", false, false, false, ""},
		{"stop", "q\n", false, true, false, ""},
		{"edit", "e\nnmap -p 22 127.0.0.1\n", true, false, true, "nmap -p 22 127.0.0.1"},
		{"edit blank denies", "e\n   \n", false, false, false, ""},
		{"eof denies", "", false, false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out strings.Builder
			allow, edited, stop := promptConfirm(bufio.NewReader(strings.NewReader(c.in)), &out, rcCmd())
			if allow != c.allow || stop != c.stop {
				t.Fatalf("allow=%v stop=%v, want allow=%v stop=%v", allow, stop, c.allow, c.stop)
			}
			if (edited != nil) != c.edited {
				t.Fatalf("edited=%v, want %v", edited != nil, c.edited)
			}
			if c.edited {
				got := strings.TrimSpace(edited.Binary + " " + strings.Join(edited.Args, " "))
				if got != c.editArgs {
					t.Fatalf("edited command = %q, want %q", got, c.editArgs)
				}
			}
			// The command is printed for the operator to see.
			if !strings.Contains(out.String(), "nmap") {
				t.Errorf("prompt did not show the command:\n%s", out.String())
			}
		})
	}
}

func TestReleaseConfirmerReleasesAndRestores(t *testing.T) {
	fr := &fakeReleaser{}
	c := releaseConfirmer{prog: fr, in: strings.NewReader("y\n"), out: &strings.Builder{}}
	allow, edited := c.ConfirmOrEdit(context.Background(), rcCmd())
	if !allow || edited != nil {
		t.Fatalf("allow=%v edited=%v, want allow with no edit", allow, edited)
	}
	if fr.released != 1 || fr.restored != 1 {
		t.Fatalf("released=%d restored=%d, want 1/1 (terminal released then restored)", fr.released, fr.restored)
	}
}

func TestReleaseConfirmerStopCancels(t *testing.T) {
	fr := &fakeReleaser{}
	var canceled bool
	c := releaseConfirmer{prog: fr, in: strings.NewReader("q\n"), out: &strings.Builder{}, stop: func() { canceled = true }}
	allow, _ := c.ConfirmOrEdit(context.Background(), rcCmd())
	if allow {
		t.Fatal("q should deny")
	}
	if !canceled {
		t.Fatal("q should call the stop func to cancel the engagement")
	}
	if fr.restored != 1 {
		t.Fatalf("terminal must be restored even on stop, restored=%d", fr.restored)
	}
}

func TestReleaseConfirmerNilProgDenies(t *testing.T) {
	c := releaseConfirmer{}
	if allow, edited := c.ConfirmOrEdit(context.Background(), rcCmd()); allow || edited != nil {
		t.Fatal("a nil prog must fail closed (deny)")
	}
}

func TestReleaseAskerReadsAnswer(t *testing.T) {
	fr := &fakeReleaser{}
	c := askuser.Clarification{Question: "go?", Options: []askuser.ClarifyOption{{Label: "yes", Value: "y"}, {Label: "no", Value: "n"}}}
	res := releaseAsker{prog: fr, in: strings.NewReader("y\n"), out: &strings.Builder{}}.Ask(context.Background(), c)
	if res.Value != "y" || res.Canceled {
		t.Fatalf("asker result = %+v, want value y", res)
	}
	if fr.released != 1 || fr.restored != 1 {
		t.Fatalf("released=%d restored=%d, want 1/1", fr.released, fr.restored)
	}
}

func TestReleaseAskerNilProgCancels(t *testing.T) {
	if r := (releaseAsker{}).Ask(context.Background(), askuser.Clarification{}); !r.Canceled {
		t.Fatal("nil prog should cancel")
	}
}

func TestPromptArmDecisions(t *testing.T) {
	task := eng.Task{Kind: "exploit", Objective: "pop a shell"}
	cases := []struct {
		in   string
		want ArmDecision
	}{
		{"y\n", ArmApprove}, {"yes\n", ArmApprove}, {"n\n", ArmSkip}, {"\n", ArmSkip}, {"q\n", ArmStop}, {"", ArmSkip},
	}
	for _, c := range cases {
		var out strings.Builder
		if got := promptArm(bufio.NewReader(strings.NewReader(c.in)), &out, task); got != c.want {
			t.Errorf("promptArm(%q) = %v, want %v", c.in, got, c.want)
		}
		if !strings.Contains(out.String(), "pop a shell") {
			t.Errorf("arm prompt missing the task objective for input %q", c.in)
		}
	}
}

func TestReleaseArmRequesterReleasesAndNilSkips(t *testing.T) {
	fr := &fakeReleaser{}
	if d := (releaseArmRequester{prog: fr, in: strings.NewReader("y\n"), out: &strings.Builder{}}).RequestArm(context.Background(), eng.Task{Kind: "x", Objective: "y"}); d != ArmApprove {
		t.Fatalf("arm = %v, want ArmApprove", d)
	}
	if fr.released != 1 || fr.restored != 1 {
		t.Fatalf("released=%d restored=%d", fr.released, fr.restored)
	}
	if d := (releaseArmRequester{}).RequestArm(context.Background(), eng.Task{}); d != ArmSkip {
		t.Fatalf("nil prog arm = %v, want ArmSkip", d)
	}
}
