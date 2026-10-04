package structgen

import (
	"strings"
	"testing"

	"blkchain/cli/internal/promptguard"
)

func TestSystemPromptIncludesUntrustedInputClause(t *testing.T) {
	if !strings.Contains(systemPrompt, promptguard.UntrustedInputClause) {
		t.Fatalf("system prompt is missing the shared input clause")
	}
}
