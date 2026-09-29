package modeleval

import (
	"fmt"
	"math"
	"time"
)

// TokensPerSec is tokens/second, guarding against a zero or negative duration
// (which would divide by zero) and a zero token count.
func TokensPerSec(tokens int, d time.Duration) float64 {
	if tokens <= 0 || d <= 0 {
		return 0
	}
	return float64(tokens) / d.Seconds()
}

// ScoreSanity counts non-finite and out-of-range reranker scores. A nil element
// is a JSON null (httputil sanitized a source NaN/Inf) and counts as
// non-finite. Model scores are sigmoid outputs, so anything outside [0,1] is
// out of range (e.g. the -1.0 blank-document sentinel).
func ScoreSanity(scores []*float64) (nonFinite, outOfRange int) {
	for _, s := range scores {
		if s == nil || math.IsNaN(*s) || math.IsInf(*s, 0) {
			nonFinite++
			continue
		}
		if *s < 0 || *s > 1 {
			outOfRange++
		}
	}
	return nonFinite, outOfRange
}

// FormatElapsed renders a duration compactly: sub-second as whole ms, otherwise
// seconds to one decimal.
func FormatElapsed(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
