package main

import "testing"

func TestRunOutputsContains(t *testing.T) {
	r := NewRunOutputs()
	if r.Contains("t1", "anything") {
		t.Error("nothing captured yet")
	}
	r.Add("t1", "PORT 22/tcp open ssh")
	if !r.Contains("t1", "22/tcp open") {
		t.Error("substring of captured output should verify")
	}
	if r.Contains("t1", "not present") {
		t.Error("absent quote must not verify")
	}
	if r.Contains("t2", "22/tcp open") {
		t.Error("wrong task must not verify")
	}
	if r.Contains("t1", "") {
		t.Error("empty quote must not verify")
	}
}
