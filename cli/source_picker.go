package main

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type sourceSelectedMsg struct{ target openTarget }

type sourcePicker struct {
	items    []openTarget
	selected int
	preview  string
}

func (p sourcePicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch k.String() {
	case "esc":
		if p.preview != "" {
			p.preview = ""
			return p, nil
		}
		return p, closeOverlayCmd
	case "up":
		p.selected = max(p.selected-1, 0)
		p.preview = ""
	case "down":
		p.selected = min(p.selected+1, max(len(p.items)-1, 0))
		p.preview = ""
	case "enter":
		if len(p.items) > 0 {
			target := p.items[p.selected]
			return p, func() tea.Msg { return sourceSelectedMsg{target: target} }
		}
	case "p":
		if len(p.items) == 0 {
			return p, nil
		}
		item := p.items[p.selected]
		if isWebURL(item.Path) {
			p.preview = "URL reference, not fetched:\n" + sanitizeTerminal(redactedURL(item.Path))
			return p, nil
		}
		path, err := resolveSourcePath(item.Path)
		if err != nil {
			p.preview = "preview: " + sanitizeTerminal(err.Error())
			return p, nil
		}
		text, err := readAttachment(path)
		if err != nil {
			p.preview = "preview: " + sanitizeTerminal(err.Error())
		} else {
			p.preview = sanitizeTerminal(text)
		}
	}
	return p, nil
}

func (p sourcePicker) View(width, height int) string {
	body := func(w, rows int) string {
		if p.preview != "" {
			lines := strings.Split(wrapIndent(p.preview, 0, w), "\n")
			return strings.Join(lines[:min(rows, len(lines))], "\n")
		}
		if len(p.items) == 0 {
			return Meta.Render("no cited sources yet")
		}
		start := max(p.selected-rows+1, 0)
		var lines []string
		for i := start; i < min(start+rows, len(p.items)); i++ {
			marker := "  "
			if i == p.selected {
				marker = Glyph(GlyphPrompt) + " "
			}
			path := p.items[i].Path
			if isWebURL(path) {
				path = redactedURL(path)
			}
			label := strconv.Itoa(i+1) + " " + path
			if p.items[i].Section != "" {
				label += " | " + p.items[i].Section
			}
			lines = append(lines, marker+ellipsize(oneLine(sanitizeTerminal(label)), max(w-2, 1)))
		}
		return strings.Join(lines, "\n")
	}
	want := clamp(len(p.items), 1, 9)
	if p.preview != "" {
		want = 10
	}
	return overlayBox(overlaySpec{title: fmt.Sprintf("SOURCES (%d)", len(p.items)), wantW: 72, wantRows: want, body: body}, width, height)
}
