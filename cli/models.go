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
	"blkchain/cli/internal/ragconfig"
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

	if jsonOut {
		return emitReportsJSON(os.Stdout, reports)
	}

	fmt.Println(H1.Render("blk models"))
	fmt.Println()
	for _, r := range reports {
		fmt.Println(renderReport(r))
	}
	return nil
}

// modelsConfig resolves probe config from the env, reusing llm.go's oMLX
// resolution and the stack's embed_server port (8100).
func modelsConfig() modeleval.Config {
	embedBase := strings.TrimRight(ragconfig.Load().EmbedServerURL, "/")
	return modeleval.Config{
		ChatBaseURL:    omlxBaseURL(),
		ChatAPIKey:     strings.TrimSpace(os.Getenv("OMLX_API_KEY")),
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

// emitReportsJSON writes the reports as strict JSON for scripting. Errors are
// rendered as their message string.
func emitReportsJSON(w io.Writer, reports []modeleval.ModelReport) error {
	type jsonReport struct {
		Model   string                `json:"model"`
		Ready   bool                  `json:"ready"`
		ReadyMs int64                 `json:"ready_ms"`
		Error   string                `json:"error,omitempty"`
		Perf    *modeleval.PerfResult `json:"perf,omitempty"`
	}
	out := make([]jsonReport, 0, len(reports))
	for _, r := range reports {
		jr := jsonReport{Model: r.Kind.String(), Ready: r.Ready, ReadyMs: r.ReadyElapsed.Milliseconds(), Perf: r.Perf}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		out = append(out, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
