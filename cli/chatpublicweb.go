package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
	"blkchain/cli/internal/webacquire"
	"golang.org/x/net/html"
)

const chatPublicQueryMaxBytes = 512

var chatOpaqueToken = regexp.MustCompile(`(?i)\b(?:sk[-_][a-z0-9]{8,}|gh[pousr]_[a-z0-9]{8,}|akia[0-9a-z]{16}|[a-z0-9_=-]{40,})\b`)

type chatWebProvenance struct {
	urls     map[string]bool
	evidence []string
}

func (p *chatWebProvenance) record(value string) {
	if len(p.evidence) >= 4 {
		return
	}
	value = capRunes(value, 8000)
	for _, prior := range p.evidence {
		if prior == value {
			return
		}
	}
	p.evidence = append(p.evidence, value)
}

func chatPublicQueryAllowed(query, question string, history []priorTurn) bool {
	if query == "" || len(query) > chatPublicQueryMaxBytes || strings.ContainsAny(query, "\r\n\x00") ||
		strings.Contains(query, "://") || chatOpaqueToken.MatchString(query) || targetSecretPattern.MatchString(query) {
		return false
	}
	for _, field := range strings.Fields(query) {
		field = strings.Trim(field, `[](){}<>"'.,;!?`)
		if ip := net.ParseIP(field); ip != nil {
			return false
		}
	}
	for _, text := range append([]priorTurn{{Role: "human", Content: question}}, history...) {
		if chatType(text.Role) != "human" {
			continue
		}
		for _, target := range chatTargetEntries(text.Content, nil) {
			if strings.Contains(strings.ToLower(query), strings.ToLower(target)) {
				return false
			}
		}
	}
	return true
}

type chatWebSearchArgs struct {
	Query string `json:"query,omitempty" desc:"public search query; omit to use the current question"`
	Limit int    `json:"limit,omitempty" desc:"result limit, at most 20"`
}

func newChatWebSearchTool(cfg ragconfig.Config, question string, history []priorTurn, provenance *chatWebProvenance) tooldef.Tool {
	return newStoreTool("web_search", "Search public sources. Model-generated queries are screened for target details and secret-shaped data.", chatWebSearchArgs{},
		func(ctx context.Context, args string) (string, error) {
			var in chatWebSearchArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "web_search: invalid arguments", nil
			}
			query := strings.TrimSpace(in.Query)
			if query == "" {
				query = question
			}
			if !chatPublicQueryAllowed(query, question, history) {
				return "web_search: query contains target details or sensitive data", nil
			}
			limit := cfg.TavilyMaxResults
			if limit < 1 {
				limit = 5
			}
			if in.Limit > 0 {
				limit = in.Limit
			}
			if limit < 1 || limit > webMaxResults {
				return "web_search: limit must be 1 to 20", nil
			}
			results, err := webSearch(ctx, tavilyKey(), query, limit, primarySearchDomains(query))
			if err != nil {
				return "web_search: " + err.Error(), nil
			}
			if len(results) == 0 {
				return "web_search: no results", nil
			}
			var out strings.Builder
			for i, result := range results {
				if _, err := webacquire.URL(result.Payload.Path); err != nil {
					continue
				}
				fmt.Fprintf(&out, "[%d] %s\n%s\n%s\n", i+1, result.Payload.Section, result.Payload.Path, capRunes(result.Payload.Text, 1200))
				provenance.urls[result.Payload.Path] = true
			}
			if out.Len() == 0 {
				return "web_search: no valid source URLs", nil
			}
			bounded := capRunes(out.String(), 8000)
			provenance.record(bounded)
			return secgate.WrapUntrusted("web", bounded), nil
		})
}

func chatPublicBroker() *webacquire.Broker {
	return &webacquire.Broker{Policy: webacquire.Policy{
		Authorize: func(_ context.Context, request webacquire.Request) error {
			if request.Method != "GET" || len(request.Body) > 0 || len(request.Headers) > 0 {
				return fmt.Errorf("public extraction accepts GET without request data")
			}
			return nil
		},
		IPAllowed: func(_ string, ip net.IP) bool {
			return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
		},
		MaxBodyBytes:  1 << 20,
		MaxTotalBytes: 4 << 20,
		MaxRequests:   3,
	}}
}

func chatHTMLText(body []byte) string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return string(body)
	}
	var out strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "script", "style", "noscript", "svg", "nav", "footer":
				return
			case "p", "div", "article", "section", "h1", "h2", "h3", "li", "br":
				out.WriteByte('\n')
			}
		}
		if node.Type == html.TextNode {
			out.WriteString(node.Data)
			out.WriteByte(' ')
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	lines := strings.Split(out.String(), "\n")
	for i := range lines {
		lines[i] = strings.Join(strings.Fields(lines[i]), " ")
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

type chatWebExtractArgs struct {
	URL      string `json:"url" desc:"public URL from the user request or a search result in this turn"`
	MaxChars int    `json:"max_chars,omitempty" desc:"maximum returned characters, at most 16000"`
}

func newChatWebExtractTool(question string, provenance *chatWebProvenance) tooldef.Tool {
	return newStoreTool("web_extract", "Fetch and extract text from a public URL supplied by the user or returned by web_search this turn.", chatWebExtractArgs{},
		func(ctx context.Context, args string) (string, error) {
			var in chatWebExtractArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "web_extract: invalid arguments", nil
			}
			u, err := webacquire.URL(in.URL)
			if err != nil {
				return "web_extract: " + err.Error(), nil
			}
			if !strings.Contains(question, in.URL) && !provenance.urls[in.URL] {
				return "web_extract: URL must come from the user request or this turn's search results", nil
			}
			if strings.ContainsAny(u.RawQuery+u.Path, "\r\n\x00") || chatOpaqueToken.MatchString(u.RawQuery+u.Path) {
				return "web_extract: URL contains sensitive data", nil
			}
			limit := in.MaxChars
			if limit == 0 {
				limit = 8000
			}
			if limit < 1 || limit > 16000 {
				return "web_extract: max_chars must be 1 to 16000", nil
			}
			out, err := chatPublicBroker().Fetch(ctx, webacquire.Request{Method: "GET", URL: in.URL})
			if err != nil {
				return "web_extract: " + err.Error(), nil
			}
			contentType := strings.ToLower(out.Headers.Get("Content-Type"))
			if !strings.HasPrefix(contentType, "text/") && !strings.Contains(contentType, "json") && !strings.Contains(contentType, "xml") {
				return "web_extract: unsupported content type", nil
			}
			body := string(out.Body)
			if strings.Contains(contentType, "html") {
				body = chatHTMLText(out.Body)
			}
			body = capRunes(body, limit)
			result := fmt.Sprintf("URL: %s\nStatus: %d\n%s", out.FinalURL, out.Status, body)
			provenance.record(result)
			return secgate.WrapUntrusted("web", result), nil
		})
}
