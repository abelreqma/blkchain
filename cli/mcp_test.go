package main

import (
	"encoding/json"
	"testing"
)

func TestMCPSearchInputDecodes(t *testing.T) {
	var in mcpSearchIn
	if err := json.Unmarshal([]byte(`{"query":"ssrf","top_k":3}`), &in); err != nil || in.Query != "ssrf" || in.TopK == nil || *in.TopK != 3 {
		t.Fatalf("decode: %+v err=%v", in, err)
	}
}

func TestMCPSearchInputTopKOmitted(t *testing.T) {
	var in mcpSearchIn
	if err := json.Unmarshal([]byte(`{"query":"lfi to rce"}`), &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in.TopK != nil {
		t.Fatalf("expected nil TopK when omitted, got %v", *in.TopK)
	}
}

func TestMCPAnswerInputDecodes(t *testing.T) {
	var in mcpAnswerIn
	if err := json.Unmarshal([]byte(`{"query":"how do I chain this SSRF to RCE?"}`), &in); err != nil || in.Query == "" {
		t.Fatalf("decode: %+v err=%v", in, err)
	}
}
