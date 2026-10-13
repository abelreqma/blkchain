package main

import "testing"

func TestGatewayCommandIsGone(t *testing.T) {
	if _, ok := lookupCommand("gateway"); ok {
		t.Fatal("the gateway command is still registered")
	}
}
