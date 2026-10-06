package main

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type completionModelsMsg []string

func completionModelsCmd() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), modelsListTimeout)
	defer cancel()
	models, _, _ := fetchChatModels(ctx)
	var ids []string
	for _, m := range models {
		if m.ID == sanitizeTerminal(m.ID) && !strings.ContainsAny(m.ID, "\r\n\t ") && len(m.ID) <= 1024 {
			ids = append(ids, m.ID)
		}
	}
	return completionModelsMsg(ids)
}

func (m model) argumentSuggestions(value string) []paletteItem {
	input := strings.TrimPrefix(value, "/")
	verb, rest := input, ""
	if i := strings.IndexByte(input, ' '); i >= 0 {
		verb, rest = input[:i], strings.TrimLeft(input[i+1:], " ")
	}
	if action, path := splitFirst(rest); (verb == "context" && action == "add" || verb == "engage" && action == "resume") && strings.Contains(rest, " ") {
		return pathSuggestions("/"+verb+" "+action+" ", path)
	}
	var choices []string
	prefix, head := rest, "/"+verb+" "
	words := strings.Fields(rest)
	position := len(words)
	if rest != "" && !strings.HasSuffix(rest, " ") {
		position--
	}
	if len(words) > 0 && position > 0 {
		prefix = ""
		if !strings.HasSuffix(rest, " ") {
			prefix = words[len(words)-1]
		}
		head += strings.Join(words[:position], " ") + " "
	}
	switch verb {
	case "agent":
		if position == 0 {
			choices = answerAgentNames()
		}
	case "models":
		if position == 0 {
			choices = []string{"on", "off", "load", "unload"}
		} else if position == 1 && (words[0] == "on" || words[0] == "off" || words[0] == "load" || words[0] == "unload") {
			choices = append(append([]string(nil), m.completionModels...), m.currentModel())
			if words[0] == "on" || words[0] == "off" {
				choices = append(choices, "rag", "reranker", "web")
			}
		}
	case "web":
		if position == 0 {
			choices = []string{"status", "on", "off", "provider", "search"}
		} else if position == 1 && words[0] == "provider" {
			choices = []string{"auto", "duckduckgo", "tavily"}
		}
	case "engage":
		if position == 0 {
			choices = []string{"resume", "web"}
		} else if position == 1 && words[0] == "web" {
			choices = []string{"inspect", "analyze", "import", "export", "archive", "collect", "replay"}
		} else if position == 1 && words[0] == "resume" {
			return pathSuggestions(head, prefix)
		}
	case "context":
		if position == 0 {
			choices = []string{"list", "add", "preview", "remove", "clear"}
		} else if position == 1 && (words[0] == "preview" || words[0] == "remove") {
			for i := range m.attachments {
				choices = append(choices, strconv.Itoa(i+1))
			}
		} else if position == 1 && words[0] == "add" {
			return pathSuggestions(head, prefix)
		}
	case "history":
		if position == 0 {
			choices = []string{"clear"}
		}
	case "queue":
		if position == 0 {
			choices = []string{"list", "edit", "remove", "pause", "resume", "clear"}
		} else if position == 1 && (words[0] == "edit" || words[0] == "remove") {
			for i := range m.queue {
				choices = append(choices, strconv.Itoa(i+1))
			}
		}
	case "rag", "viz":
		if position == 0 {
			choices = []string{"on", "off"}
		}
	case "transcript":
		if position == 0 {
			choices = []string{"off", "important", "full"}
		}
	case "help":
		if position == 0 {
			for _, c := range slashCommands() {
				choices = append(choices, c.name)
			}
		}
	case "logs":
		if position == 0 {
			choices = []string{"embed_server"}
		}
	case "open":
		if position == 0 && (prefix == "" || prefix[0] >= '0' && prefix[0] <= '9') {
			for i := range m.openTargets {
				choices = append(choices, strconv.Itoa(i+1))
			}
		} else {
			return pathSuggestions("/open ", rest)
		}
	case "attach":
		return pathSuggestions("/attach ", rest)
	}
	sort.Strings(choices)
	var out []paletteItem
	seen := map[string]bool{}
	for _, choice := range choices {
		if choice == "" || seen[choice] || !strings.HasPrefix(strings.ToLower(choice), strings.ToLower(prefix)) {
			continue
		}
		seen[choice] = true
		label := choice
		if verb == "agent" {
			label = answerAgentLabel(choice)
		}
		out = append(out, paletteItem{name: strings.TrimPrefix(head, "/") + choice, label: label, value: head + choice + " "})
		if len(out) == 100 {
			break
		}
	}
	return out
}

func pathSuggestions(head, prefix string) []paletteItem {
	if strings.Contains(prefix, "://") {
		return nil
	}
	dir, base := filepath.Split(prefix)
	readDir := dir
	if readDir == "" {
		readDir = "."
	}
	var out []paletteItem
	for _, entry := range readDirEntries(readDir) {
		if entry.name == ".." || !strings.HasPrefix(entry.name, base) || entry.name != sanitizeTerminal(entry.name) {
			continue
		}
		value := dir + entry.name
		suffix := " "
		if entry.isDir {
			value += string(filepath.Separator)
			suffix = ""
		}
		out = append(out, paletteItem{name: strings.TrimPrefix(head, "/") + value, label: entry.name, value: head + value + suffix})
		if len(out) == 100 {
			break
		}
	}
	return out
}
