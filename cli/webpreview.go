package main

import (
	"blkchain/cli/internal/webanalysis"
	"fmt"
	"golang.org/x/net/html"
	"strings"
)

func webModelPreview(kind, out string, findings []webanalysis.Finding) string {
	if kind != "browser-dom" {
		status, _, _ := strings.Cut(out, "\n")
		return "HTTP status " + webanalysis.SafeText(status) + "; response body retained in restricted evidence\n" + webanalysis.CredentialSummary(findings)
	}
	var result strings.Builder
	tokenizer := html.NewTokenizer(strings.NewReader(out))
	hidden := ""
	for result.Len() < 16<<10 {
		typ := tokenizer.Next()
		if typ == html.ErrorToken {
			break
		}
		token := tokenizer.Token()
		if hidden != "" {
			if typ == html.EndTagToken && token.Data == hidden {
				hidden = ""
			}
			continue
		}
		if typ == html.StartTagToken && (token.Data == "script" || token.Data == "style") {
			hidden = token.Data
			continue
		}
		switch typ {
		case html.TextToken:
			result.WriteString(webanalysis.RedactText(token.Data))
		case html.StartTagToken, html.SelfClosingTagToken:
			fmt.Fprintf(&result, "\n<%s", token.Data)
			for _, attribute := range token.Attr {
				switch attribute.Key {
				case "id", "name", "type", "role", "method", "placeholder", "aria-label":
					fmt.Fprintf(&result, " %s=%q", attribute.Key, capRunes(webanalysis.RedactText(attribute.Val), 256))
				case "href", "action":
					fmt.Fprintf(&result, " %s=%q", attribute.Key, capRunes(webanalysis.RedactURL(attribute.Val), 512))
				}
			}
			result.WriteByte('>')
		}
	}
	snapshot := webanalysis.Snapshot{Findings: findings, Calls: []webanalysis.Call{{Arguments: []string{result.String()}}}}
	redacted := webanalysis.Redacted(snapshot)
	if len(redacted.Calls) == 0 {
		return "DOM preview unavailable"
	}
	return capRunes(redacted.Calls[0].Arguments[0], 16384) + "\n" + webanalysis.CredentialSummary(findings)
}
