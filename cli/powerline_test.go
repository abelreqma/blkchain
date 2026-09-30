package main

import (
	"math"
	"strings"
	"testing"
)

func TestPLCurrentTier(t *testing.T) {
	// Save original values to restore after each case.
	origColor := useColor
	origUnicode := useUnicode
	defer func() {
		useColor = origColor
		useUnicode = origUnicode
	}()

	cases := []struct {
		name       string
		color, uni bool
		env        string
		want       plTier
	}{
		{"default nerd", true, true, "", plNerd},
		{"powerline 0 unicode", true, true, "0", plUnicode},
		{"powerline 1 nerd", true, true, "1", plNerd},
		{"no color ascii", false, true, "1", plASCII},
		{"no unicode ascii", true, false, "", plASCII},
	}
	for _, c := range cases {
		useColor, useUnicode = c.color, c.uni
		t.Setenv("BLKCHAIN_POWERLINE", c.env)
		if got := plCurrentTier(); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPLMeterFill(t *testing.T) {
	// Half of 8 cells filled; ascii tier uses '#' filled and '.' empty inside brackets.
	got := plMeter(0.5, 8, plASCII)
	if !strings.Contains(got, "####") || !strings.Contains(got, "....") {
		t.Fatalf("plMeter ascii half = %q; want 4 filled and 4 empty", got)
	}

	// Clamp tests: assert the RESULT, not just no-panic.
	// Negative frac should clamp to 0, producing zero filled cells.
	gotNeg := plMeter(-1, 8, plASCII)
	if !strings.Contains(gotNeg, "[........]") {
		t.Fatalf("plMeter(-1, 8, ASCII) = %q; want all empty [........]", gotNeg)
	}

	// Frac > 1 should clamp to 1, producing all filled cells.
	gotOver := plMeter(2, 8, plASCII)
	if !strings.Contains(gotOver, "[########]") {
		t.Fatalf("plMeter(2, 8, ASCII) = %q; want all filled [########]", gotOver)
	}

	// NaN guard: NaN should clamp to 0, producing empty meter.
	gotNaN := plMeter(math.NaN(), 8, plASCII)
	if !strings.Contains(gotNaN, "[........]") {
		t.Fatalf("plMeter(NaN, 8, ASCII) = %q; want all empty [........]", gotNaN)
	}

	// Cells < 1 clamps to 1; 0.5 of 1 cell rounds to 1 filled.
	gotCellMin := plMeter(0.5, 0, plASCII)
	if !strings.Contains(gotCellMin, "[#]") {
		t.Fatalf("plMeter(0.5, 0, ASCII) = %q; want single-cell [#]", gotCellMin)
	}

	// Colored tier (unicode) should use block glyphs.
	gotColor := plMeter(0.5, 8, plUnicode)
	if !strings.Contains(gotColor, "\u2588") {
		t.Fatalf("plMeter(0.5, 8, Unicode) = %q; want filled block glyph \\u2588", gotColor)
	}
}

func TestPLRibbonSeparatorsByTier(t *testing.T) {
	segs := []plSegment{{Text: "rag"}, {Text: "model"}}

	// Unicode tier: filled right triangle U+25B6 between segments.
	uni := plRenderRibbon(segs, nil, plUnicode, 80)
	if !strings.Contains(uni, "\u25B6") {
		t.Fatalf("unicode ribbon missing U+25B6 separator: %q", uni)
	}

	// ASCII tier: should use '>' not U+25B6.
	asc := plRenderRibbon(segs, nil, plASCII, 80)
	if strings.Contains(asc, "\u25B6") || !strings.Contains(asc, ">") {
		t.Fatalf("ascii ribbon should use '>' not U+25B6: %q", asc)
	}

	// Nerd tier: powerline right separator U+E0B0.
	nerd := plRenderRibbon(segs, nil, plNerd, 80)
	if !strings.Contains(nerd, "\uE0B0") {
		t.Fatalf("nerd ribbon missing U+E0B0 separator: %q", nerd)
	}

	// Right cluster: assert left separator appears between right segments.
	rightSegs := []plSegment{{Text: "left"}}
	rightCluster := []plSegment{{Text: "first"}, {Text: "second"}}

	// Unicode tier right separator U+25C0.
	uniRight := plRenderRibbon(rightSegs, rightCluster, plUnicode, 80)
	if !strings.Contains(uniRight, "\u25C0") {
		t.Fatalf("unicode right cluster missing U+25C0 left separator: %q", uniRight)
	}

	// ASCII tier right separator '<'.
	ascRight := plRenderRibbon(rightSegs, rightCluster, plASCII, 80)
	if !strings.Contains(ascRight, "<") {
		t.Fatalf("ascii right cluster missing '<' left separator: %q", ascRight)
	}

	// Nerd tier right separator U+E0B2.
	nerdRight := plRenderRibbon(rightSegs, rightCluster, plNerd, 80)
	if !strings.Contains(nerdRight, "\uE0B2") {
		t.Fatalf("nerd right cluster missing U+E0B2 left separator: %q", nerdRight)
	}

	// Nerd icon: segment with Icon set includes icon when rendered at plNerd.
	iconSeg := plSegment{Text: "model", Icon: "\uF85A"} // example nerd glyph
	iconOnly := []plSegment{iconSeg}
	nerdIcon := plRenderRibbon(iconOnly, nil, plNerd, 80)
	if !strings.Contains(nerdIcon, "\uF85A") {
		t.Fatalf("nerd ribbon with icon missing icon glyph: %q", nerdIcon)
	}
}

func TestPLRibbonThinSeparatorForSameBG(t *testing.T) {
	const thin, hard = "\u2502", "\u25B6"

	same := []plSegment{{Text: "a", BG: Surface}, {Text: "b", BG: Surface}}
	got := plRenderRibbon(same, nil, plUnicode, 80)
	if !strings.Contains(got, thin) {
		t.Errorf("same-BG segments lack the thin separator: %q", got)
	}
	// Only the cluster-boundary arrow remains.
	if n := strings.Count(got, hard); n != 1 {
		t.Errorf("same-BG segments: %d hard arrows, want 1 (boundary only): %q", n, got)
	}

	diff := []plSegment{{Text: "a", BG: Surface}, {Text: "b", BG: Success}}
	got = plRenderRibbon(diff, nil, plUnicode, 80)
	if strings.Contains(got, thin) {
		t.Errorf("different-BG segments got a thin separator: %q", got)
	}
	if n := strings.Count(got, hard); n != 2 {
		t.Errorf("different-BG segments: %d hard arrows, want 2: %q", n, got)
	}

	// Right cluster: same BG uses the thin separator, different BG the arrow.
	const leftHard = "\u25C0"
	got = plRenderRibbon(nil, same, plUnicode, 80)
	if !strings.Contains(got, thin) || strings.Count(got, leftHard) != 1 {
		t.Errorf("right cluster same-BG: %q", got)
	}
	got = plRenderRibbon(nil, diff, plUnicode, 80)
	if strings.Contains(got, thin) || strings.Count(got, leftHard) != 2 {
		t.Errorf("right cluster different-BG: %q", got)
	}

	// Nerd tier uses the powerline thin glyphs.
	if got := plRenderRibbon(same, nil, plNerd, 80); !strings.Contains(got, "\uE0B1") {
		t.Errorf("nerd same-BG lacks U+E0B1: %q", got)
	}
	if got := plRenderRibbon(nil, same, plNerd, 80); !strings.Contains(got, "\uE0B3") {
		t.Errorf("nerd right same-BG lacks U+E0B3: %q", got)
	}
}
