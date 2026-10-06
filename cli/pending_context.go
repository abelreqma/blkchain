package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

const maxPendingItems = 16
const maxPendingBytes = 128 << 10

var contextURLPattern = regexp.MustCompile(`(?i)https?://[^\s<>"'` + "`" + `]+`)

func contextURLs(text string) []string {
	return contextURLRefs(text, maxPendingItems)
}

func contextURLRefs(text string, limit int) []string {
	if len(text) > maxPendingBytes {
		text = text[:maxPendingBytes]
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range contextURLPattern.FindAllString(text, -1) {
		if raw != strings.TrimSpace(text) {
			raw = strings.TrimRight(raw, ".,;!")
			for _, pair := range [][2]string{{"(", ")"}, {"[", "]"}, {"{", "}"}} {
				for strings.HasSuffix(raw, pair[1]) && strings.Count(raw, pair[1]) > strings.Count(raw, pair[0]) {
					raw = strings.TrimSuffix(raw, pair[1])
				}
			}
		}
		if len(raw) > 2048 || seen[raw] {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.User != nil || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") {
			continue
		}
		seen[raw] = true
		out = append(out, raw)
		if len(out) == limit {
			break
		}
	}
	return out
}

func (m *model) addPendingContext(value string) error {
	value = strings.TrimSpace(value)
	if len(value) > maxPendingBytes {
		return fmt.Errorf("context input exceeds the size limit")
	}
	links := contextURLRefs(value, maxPendingItems+1)
	if len(links) > maxPendingItems {
		return fmt.Errorf("pending context limit reached; add at most %d links", maxPendingItems)
	}
	if len(links) > 0 {
		pending := *m
		pending.attachments = append([]attachment(nil), m.attachments...)
		for _, link := range links {
			if err := pending.appendPending(attachment{path: link, url: true}); err != nil {
				return err
			}
		}
		m.attachments = pending.attachments
		return nil
	}
	if strings.Contains(value, "://") {
		return fmt.Errorf("context: provide a credential-free HTTP(S) URL")
	}
	content, err := readAttachment(value)
	if err != nil {
		return err
	}
	return m.appendPending(attachment{path: value, content: content})
}

func (m *model) appendPending(a attachment) error {
	bytes := len(a.content) + len(a.path)
	for _, old := range m.attachments {
		if old.path == a.path {
			return nil
		}
		bytes += len(old.content) + len(old.path)
	}
	if len(m.attachments) >= maxPendingItems || bytes > maxPendingBytes {
		return fmt.Errorf("pending context limit reached; remove an item first")
	}
	m.attachments = append(m.attachments, a)
	return nil
}

func contextItemLabel(a attachment) string {
	if a.url {
		return "link " + sanitizeTerminal(redactedURL(a.path)) + " (reference, not fetched)"
	}
	return fmt.Sprintf("%s (%d bytes, next question)", sanitizeTerminal(filepath.Base(a.path)), len(a.content))
}

func (m model) contextSummary() string {
	n := len(m.attachments) + len(contextURLs(m.ta.Value()))
	if n == 0 && m.ambient == "" {
		return ""
	}
	parts := []string{"/context"}
	if len(m.attachments) > 0 {
		a := m.attachments[0]
		label := fmt.Sprintf("%s (%dB)", filepath.Base(a.path), len(a.content))
		if a.url {
			label = "link " + redactedURL(a.path)
		}
		parts = append(parts, sanitizeTerminal(label))
		if n > 1 {
			parts = append(parts, fmt.Sprintf("+%d items", n-1))
		}
	} else if n > 0 {
		parts = append(parts, fmt.Sprintf("%d draft links", n))
	}
	if m.ambient != "" {
		parts = append(parts, "project")
	}
	return Meta.Render(ellipsize(strings.Join(parts, " | "), m.renderWidth()))
}

func (m model) contextText() string {
	var lines []string
	if m.ambient != "" {
		lines = append(lines, "Project context (.blk/context.md), this session")
	}
	for i, a := range m.attachments {
		lines = append(lines, fmt.Sprintf("%d  %s", i+1, contextItemLabel(a)))
	}
	for _, link := range contextURLs(m.ta.Value()) {
		lines = append(lines, "Draft URL: "+sanitizeTerminal(redactedURL(link))+" (reference)")
	}
	if len(lines) == 0 {
		return "no pending context"
	}
	return strings.Join(lines, "\n")
}

func (m *model) contextAction(arg string) (string, error) {
	if verb, value := splitFirst(arg); verb == "add" {
		if value == "" {
			return "", fmt.Errorf("context add: provide a file path or HTTP(S) URL")
		}
		if err := m.addPendingContext(value); err != nil {
			return "", err
		}
		return m.contextText(), nil
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 || (len(fields) == 1 && fields[0] == "list") {
		return m.contextText(), nil
	}
	if len(fields) == 1 && fields[0] == "clear" {
		m.attachments = nil
		return "cleared pending attachments", nil
	}
	if len(fields) != 2 || (fields[0] != "remove" && fields[0] != "preview") {
		return "", fmt.Errorf("context: use list, add PATH|URL, preview N, remove N, or clear")
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 1 || n > len(m.attachments) {
		return "", fmt.Errorf("context: no pending item %s", fields[1])
	}
	a := m.attachments[n-1]
	if fields[0] == "preview" {
		if a.url {
			return contextItemLabel(a), nil
		}
		return contextItemLabel(a) + "\n" + sanitizeTerminal(a.content), nil
	}
	m.attachments = append(m.attachments[:n-1:n-1], m.attachments[n:]...)
	return "removed " + contextItemLabel(a), nil
}

type contextChangedMsg struct {
	kind string
	path string
}

type contextPicker struct {
	m        model
	selected int
	preview  bool
}

func (p contextPicker) rows() []attachment {
	rows := append([]attachment(nil), p.m.attachments...)
	for _, link := range contextURLs(p.m.ta.Value()) {
		rows = append(rows, attachment{path: link, url: true})
	}
	if p.m.ambient != "" {
		rows = append(rows, attachment{path: initContextPath, content: p.m.ambient})
	}
	return rows
}

func (p contextPicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	rows := p.rows()
	switch k.String() {
	case "esc":
		if p.preview {
			p.preview = false
			return p, nil
		}
		return p, closeOverlayCmd
	case "up":
		p.selected = max(p.selected-1, 0)
	case "down":
		p.selected = min(p.selected+1, max(len(rows)-1, 0))
	case "enter":
		p.preview = len(rows) > 0
	case "d":
		if p.preview || len(rows) == 0 {
			return p, nil
		}
		changed := contextChangedMsg{kind: "pending", path: rows[p.selected].path}
		if p.selected < len(p.m.attachments) {
			p.m.attachments = append(p.m.attachments[:p.selected:p.selected], p.m.attachments[p.selected+1:]...)
		} else if p.m.ambient != "" && p.selected == len(rows)-1 {
			changed.kind = "project"
			p.m.ambient = ""
		} else {
			changed.kind = "draft"
			p.m.setDraft(strings.ReplaceAll(p.m.ta.Value(), rows[p.selected].path, ""))
		}
		p.selected = min(p.selected, max(len(p.rows())-1, 0))
		return p, func() tea.Msg { return changed }
	}
	return p, nil
}

func (p contextPicker) View(width, height int) string {
	all := p.rows()
	body := func(w, rows int) string {
		if len(all) == 0 {
			return Meta.Render("no pending context")
		}
		if p.preview {
			a := all[min(p.selected, len(all)-1)]
			text := contextItemLabel(a)
			if !a.url {
				text += "\n" + sanitizeTerminal(a.content)
			}
			lines := strings.Split(wrapIndent(text, 0, w), "\n")
			return strings.Join(lines[:min(rows, len(lines))], "\n")
		}
		start := max(p.selected-rows+1, 0)
		var lines []string
		for i := start; i < min(start+rows, len(all)); i++ {
			label := contextItemLabel(all[i])
			marker := "  "
			if i == p.selected {
				marker = Glyph(GlyphPrompt) + " "
			}
			lines = append(lines, marker+ellipsize(label, max(w-2, 1)))
		}
		return strings.Join(lines, "\n")
	}
	want := max(len(all), 1)
	if p.preview {
		want = 10
	}
	return overlayBox(overlaySpec{title: "NEXT PROMPT", wantW: 72, wantRows: want, body: body}, width, height)
}
