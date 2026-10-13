package main

import "testing"

func TestParseEditedCommand(t *testing.T) {
	cmd, ok := parseEditedCommand("nmap -sV 10.0.0.5")
	if !ok || cmd.Binary != "nmap" || len(cmd.Args) != 2 || cmd.Args[0] != "-sV" || cmd.Args[1] != "10.0.0.5" {
		t.Fatalf("edited command=%+v ok=%v", cmd, ok)
	}
	if cmd.Phase != "" || cmd.Surface != "" || cmd.Armed {
		t.Fatalf("edited command inherited tier fields: %+v", cmd)
	}
	if _, ok := parseEditedCommand("   "); ok {
		t.Fatal("empty command parsed")
	}
}
