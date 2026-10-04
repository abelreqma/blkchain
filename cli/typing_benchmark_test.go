package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func BenchmarkDraftFrameWithStream(b *testing.B) {
	useDeadServices(b)
	m := frameModel(b)
	text := strings.Repeat("long wrapped draft words ", 1500)
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true})
	m = nm.(model)
	m.ta.SetHeight(6)
	m.working = true
	m = streamInto(m, longStream(5000), 4096)
	_ = m.View()
	b.ReportAllocs()
	for b.Loop() {
		nm, _ := m.Update(chunkMsg("tok "))
		m = nm.(model)
		_ = m.View()
	}
}
