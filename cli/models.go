package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/modeleval"
)

// defineModelsFlags declares `blk models`'s flags.
func defineModelsFlags(fs *flag.FlagSet, jsonOut *bool) {
	fs.BoolVar(jsonOut, "json", false, "print the reports as JSON instead of formatted text")
}

// runModels implements `blk models`: a per-model readiness + live performance
// dashboard for the three local models (chat, embed, rerank). Each model probes
// independently; one being down never aborts the others.
func runModels(args []string) error {
	var jsonOut bool
	fs := newFlagSet("models")
	defineModelsFlags(fs, &jsonOut)
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	cfg := modelsConfig()
	ctx := context.Background()

	// Probe concurrently; each is independent.
	reports := make([]modeleval.ModelReport, 3)
	var wg sync.WaitGroup
	probes := []func(context.Context, modeleval.Config) modeleval.ModelReport{
		modeleval.ProbeChat, modeleval.ProbeEmbed, modeleval.ProbeRerank,
	}
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p func(context.Context, modeleval.Config) modeleval.ModelReport) {
			defer wg.Done()
			reports[i] = p(ctx, cfg)
		}(i, p)
	}
	wg.Wait()

	prefs, provider := loadPrefs(), activeWebProvider()
	if jsonOut {
		return emitReportsJSON(os.Stdout, reports, prefs, provider)
	}

	fmt.Println(H1.Render("blk models"))
	fmt.Println()
	fmt.Print(renderModelsText(reports, prefs, provider))
	return nil
}

// renderModelsText is the text report: one line per model, the reranker marked
// when /models turned it off, then web search and any hidden chat models.
// provider is the active web-search provider (activeWebProvider): the web row
// names it and composes it with the web switch.
func renderModelsText(reports []modeleval.ModelReport, p modelPrefs, provider string) string {
	var b strings.Builder
	for _, r := range reports {
		line := renderReport(r)
		if r.Kind == modeleval.KindRerank && !p.Rerank {
			line += "   " + Caut.Render("off: answers skip the reranker")
		}
		b.WriteString(line + "\n")
	}
	ragLine := "on"
	if !p.Rag {
		ragLine = "off: answers never query the local knowledge base"
	}
	fmt.Fprintf(&b, " %s %s\n", Key.Render(fmt.Sprintf("%-7s", "rag")), Meta.Render(ragLine))
	web := "off (no provider; set TAVILY_SETUP_TOKEN or BLKCHAIN_WEB_FALLBACK=duckduckgo)"
	switch provider {
	case webProviderTavily:
		web = "off (tavily configured)"
		if p.Web {
			web = "on (tavily)"
		}
	case webProviderDuckDuckGo:
		web = "off (duckduckgo fallback configured)"
		if p.Web {
			web = "on (duckduckgo fallback)"
		}
	}
	fmt.Fprintf(&b, " %s %s\n", Key.Render(fmt.Sprintf("%-7s", "web")), Meta.Render(web))
	if len(p.Hidden) > 0 {
		hidden := make([]string, len(p.Hidden))
		for i, id := range p.Hidden {
			hidden[i] = oneLine(sanitizeTerminal(id))
		}
		fmt.Fprintf(&b, " %s %s\n", Key.Render(fmt.Sprintf("%-7s", "hidden")), Meta.Render(strings.Join(hidden, ", ")))
	}
	return b.String()
}

// modelsConfig resolves probe config from the env and the RAG config, reusing
// llm.go's oMLX resolution.
func modelsConfig() modeleval.Config {
	embedBase := strings.TrimRight(loadConfig().EmbedServerURL, "/")
	return modeleval.Config{
		ChatBaseURL:    omlxBaseURL(),
		ChatAPIKey:     omlxAPIKey(),
		ChatModel:      strings.TrimSpace(os.Getenv("OMLX_MODEL")),
		EmbedHealthURL: embedBase + "/health",
		EmbedURL:       embedBase + "/embed",
		RerankURL:      embedBase + "/rerank",
		ReadyTimeout:   30 * time.Second,
		ProbeTimeout:   60 * time.Second,
	}
}

// renderReport formats one model's report as a single themed line (pure: builds
// a string, prints nothing), so it is unit-testable.
func renderReport(r modeleval.ModelReport) string {
	name := Key.Render(fmt.Sprintf("%-7s", r.Kind.String()))

	if r.Err != nil && !r.Ready {
		return fmt.Sprintf(" %s %s %s", name, Fail.Render(Glyph(GlyphErr)),
			Meta.Render(sanitizeTerminal(r.Err.Error())))
	}

	ready := fmt.Sprintf("%s ready %s", OK.Render(Glyph(GlyphOK)),
		Meta.Render(modeleval.FormatElapsed(r.ReadyElapsed)))

	var metrics string
	switch r.Kind {
	case modeleval.KindChat:
		if r.Perf != nil {
			tps := fmt.Sprintf("%.0f tok/s", r.Perf.TokensPerSec)
			if !r.Perf.UsageReported {
				tps = "~" + tps
			}
			metrics = fmt.Sprintf("%s   %s   %s",
				Key.Render(tps),
				Meta.Render(fmt.Sprintf("ttft %s", modeleval.FormatElapsed(r.Perf.TTFT))),
				Meta.Render(sanitizeTerminal(r.Perf.ModelID)))
		}
	case modeleval.KindEmbed:
		if r.Perf != nil {
			metrics = Meta.Render(fmt.Sprintf("%d-dim   %.1f ms/vec", r.Perf.Dim, r.Perf.MsPerVector))
		}
	case modeleval.KindRerank:
		if r.Perf != nil {
			metrics = Meta.Render(fmt.Sprintf("%d docs   %.0f ms", r.Perf.PoolSize, r.Perf.Ms))
			if r.Perf.NonFinite > 0 {
				metrics += "   " + Caut.Render(fmt.Sprintf("%s %d non-finite", Glyph(GlyphWarn), r.Perf.NonFinite))
			} else if r.Perf.OutOfRange > 0 {
				metrics += "   " + Caut.Render(fmt.Sprintf("%s %d out-of-range", Glyph(GlyphWarn), r.Perf.OutOfRange))
			} else {
				metrics += "   " + Meta.Render("scores ok")
			}
		}
	}

	line := fmt.Sprintf(" %s %s   %s", name, ready, metrics)
	// A ready-but-perf-failed model shows the probe error after the ready mark.
	if r.Err != nil {
		line += "   " + Caut.Render(Glyph(GlyphWarn)+" "+sanitizeTerminal(r.Err.Error()))
	}
	return strings.TrimRight(line, " ")
}

// emitReportsJSON writes the reports as strict JSON for scripting, with DEL and
// the C1 controls escaped like printJSON. Errors are rendered as their message
// string. enabled is the /models switch (always true
// for chat and embed), the chat entry lists the hidden chat models, and a web
// entry reports web search: ready when it is configured.
func emitReportsJSON(w io.Writer, reports []modeleval.ModelReport, p modelPrefs, provider string) error {
	type jsonReport struct {
		Model    string                `json:"model"`
		Ready    bool                  `json:"ready"`
		ReadyMs  int64                 `json:"ready_ms"`
		Enabled  bool                  `json:"enabled"`
		Provider string                `json:"provider,omitempty"`
		Hidden   []string              `json:"hidden,omitempty"`
		Error    string                `json:"error,omitempty"`
		Perf     *modeleval.PerfResult `json:"perf,omitempty"`
	}
	out := make([]jsonReport, 0, len(reports)+1)
	for _, r := range reports {
		jr := jsonReport{Model: r.Kind.String(), Ready: r.Ready, ReadyMs: r.ReadyElapsed.Milliseconds(), Enabled: true, Perf: r.Perf}
		switch r.Kind {
		case modeleval.KindRerank:
			jr.Enabled = p.Rerank
		case modeleval.KindChat:
			jr.Hidden = p.Hidden
		}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		out = append(out, jr)
	}
	out = append(out, jsonReport{Model: "rag", Ready: true, Enabled: p.Rag})
	out = append(out, jsonReport{Model: "web", Ready: provider != webProviderNone, Enabled: p.Web, Provider: provider})
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(escapeJSONControls(data), '\n'))
	return err
}
