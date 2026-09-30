package main

import (
	"fmt"
	"sync"
	"testing"
)

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

func TestRunOutputsConcurrent(t *testing.T) {
	r := NewRunOutputs()
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) { defer wg.Done(); r.Add("t1", fmt.Sprintf("chunk-%d", i)) }(i)
		go func() { defer wg.Done(); r.Contains("t1", "chunk") }()
	}
	wg.Wait()
	if !r.Contains("t1", "chunk-0") && !r.Contains("t1", "chunk-99") {
		t.Errorf("expected some chunk recorded")
	}
}
