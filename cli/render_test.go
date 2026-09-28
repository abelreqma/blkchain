package main

import (
	"strings"
	"testing"
)

func TestGlowRenderNonEmpty(t *testing.T) {
	out := glowRender("# Heading\n\nSome **bold** prose.", 80)
	if strings.TrimSpace(out) == "" {
		t.Fatal("glowRender returned empty output for non-empty markdown")
	}
	if !strings.Contains(out, "Heading") {
		t.Errorf("glowRender output missing heading text, got:\n%s", out)
	}
	if !strings.Contains(out, "bold") {
		t.Errorf("glowRender output missing body text, got:\n%s", out)
	}
}

func TestGlowRenderNoANSIWhenColorDisabled(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := glowRender("# Heading\n\nSome **bold** prose with `code`.", 80)
	if strings.TrimSpace(out) == "" {
		t.Fatal("glowRender returned empty output")
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("glowRender emitted an ANSI escape with color disabled:\n%q", out)
	}
}

func TestHeaderLine(t *testing.T) {
	got := headerLine("left", "right")
	if !strings.HasPrefix(got, "left") || !strings.HasSuffix(got, "right") {
		t.Fatalf("headerLine(%q, %q) = %q, want left...right", "left", "right", got)
	}
}
