package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// cloudExecutor runs a task on the generic cloud surface (unknown or other CSP).
// It embeds genericExecutor to reuse the vantage check, gate stamping, and the
// generic non-recon paths (exploitation lifecycle + generic loop), and overrides
// recon with a cloud-specific driver so discovered evidence correlates to cloud
// findings (metadata-credential exposure, storage exposure, IAM misconfiguration).
type cloudExecutor struct {
	genericExecutor
}

func init() {
	registerExecutor(engagement.SurfaceCloud, func(d engageDeps) surfaceExecutor {
		return cloudExecutor{genericExecutor{d: d}}
	})
	registerLadder(engagement.SurfaceCloud, cloudLadder)
}

var cloudLadder = reconLadder{
	{Index: 0, Name: "public-asset-discovery", Dimensions: []string{"cloud-assets"}},
	{Index: 1, Name: "service-endpoint-fingerprint", Dimensions: []string{"cloud-endpoints", "cloud-services"}},
	{Index: 2, Name: "metadata-iam-probe", Dimensions: []string{"cloud-metadata", "cloud-iam"}},
	{Index: 3, Name: "finding-driven", Dimensions: []string{"cloud-findings"}},
}

func (e cloudExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {
	if e.d.ReconTiers && task.Phase == engagement.PhaseRecon && e.d.Gate != nil && e.d.Runs != nil {
		v, err := e.d.Store.Vantage(ctx)
		if err != nil {
			return fmt.Sprintf("executor: task %s could not read the engagement vantage: %v", task.ID, err), nil
		}
		if v != "" && !v.Reaches(task.Surface) {
			return fmt.Sprintf("executor: task %s surface %q is not reachable at the current vantage %q; advance the vantage first", task.ID, task.Surface, v), nil
		}
		return e.cloudRunReconPhase(ctx, task, v)
	}
	return e.genericExecutor.Run(ctx, task)
}

// cloudPersona returns the shared "cloud" persona (cli/domains.go). All four cloud
// surfaces use it; the task's Kind may be a CSP label, so the persona is resolved
// by name rather than by Kind, guaranteeing one persona per surface.
func cloudPersona() domain { return domainFor("cloud") }

// cloudVantageSkew returns the non-binding technique guidance appended to each
// cloud recon tier prompt for the current vantage. Vantage is CONTEXT, not a
// persona axis (one "cloud" persona for all four surfaces): the skew steers the
// model's technique choice and its kb_search/route_skill queries toward what the
// access state makes reachable. External (no foothold) skews to public-asset and
// leaked-credential discovery; post-foothold (internal and beyond) skews to
// instance-metadata credential theft and IAM privilege-escalation. An unset
// vantage ("") returns "" (legacy, no skew). All four cloud surfaces share this
// because they inherit cloudExecutor.Run -> cloudRunReconPhase.
func cloudVantageSkew(v engagement.Vantage) string {
	switch v {
	case engagement.VantageExternalUnauth, engagement.VantageExternalAuth:
		return "Vantage context (external, no foothold): skew this tier toward public-asset and leaked-credential discovery - enumerate publicly exposed cloud assets (open storage buckets/containers, exposed endpoints and APIs, DNS and CDN origins) and hunt leaked keys/credentials; reach instance metadata only through an SSRF in an in-scope exposed application. Bias your kb_search and route_skill queries to external cloud exposure and credential leakage."
	case engagement.VantageInternalFoothold, engagement.VantageLocalElevated, engagement.VantageLateralDomain:
		return "Vantage context (post-foothold): skew this tier toward instance-metadata (IMDS) credential theft and IAM enumeration plus IAM privilege-escalation primitives (PassRole, token-creator, role-assignment abuse), then lateral movement across accounts, projects, or tenants. Bias your kb_search and route_skill queries to metadata credential theft and cloud IAM privesc."
	default:
		return ""
	}
}

// cloudRunReconPhase runs the cloud recon tier ladder for one recon-phase task. It
// mirrors genericExecutor.runReconPhase but drives the cloud persona, appends the
// vantage skew to every tier prompt (vantage-as-context, wired via cloudVantageSkew
// so technique selection and the model's kb_search/route_skill queries skew
// external vs post-foothold), and calls the cloud-specific correlation (Go
// embedding has no virtual dispatch, so the cloud executor cannot rely on
// genericExecutor.runReconPhase to call cloud correlation). The ladder is selected
// by task.Surface (ladderFor), so the per-CSP executors that inherit this method
// get their own provider-refined ladder, and v threads the current engagement
// vantage from Run so all four surfaces skew by vantage identically.
func (e cloudExecutor) cloudRunReconPhase(ctx context.Context, task engagement.Task, v engagement.Vantage) (string, error) {
	runTimeout, runCap := resolveRunCaps()
	execDir, cleanup, err := newExecutorScratchDir(e.d.WorkDir)
	if err != nil {
		return "", err
	}
	defer cleanup()

	cmdCtx := secgate.Command{
		Phase:   secgate.Phase(string(task.Phase)),
		Surface: secgate.Surface(string(task.Surface)),
		Armed:   task.Armed,
	}
	grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
	activeTask := func() string { return task.ID }

	reg := tooldef.NewRegistry()
	for _, t := range []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
		newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder),
		newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
	} {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	dom := cloudPersona()

	// Vantage-as-context, wired: the skew is appended to every tier prompt below so
	// technique selection and the model's kb_search/route_skill queries skew external
	// (public-asset / leaked-credential discovery) vs post-foothold (metadata / IAM
	// privesc). Empty for an unset vantage (legacy, no skew).
	skew := cloudVantageSkew(v)

	var exploitSel exploitSelector
	if e.d.RC != nil {
		exploitSel = newKBExploitSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}

	runTier := func(ctx context.Context, _ engagement.Surface, asset string, tier reconTier, sel reconSelection) (tierOutcome, error) {
		beforeCmds := e.d.Runs.Count(task.ID)
		beforeRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		human := reconTierPrompt(task, asset, tier, sel)
		if skew != "" {
			human = human + "\n" + skew
		}
		msgs := []llms.MessageContent{
			{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
			{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(human)}},
		}
		if _, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
			return tierOutcome{}, err
		}

		newRows, err := e.captureTierEvidence(task.ID, string(task.Surface), asset, tier.Name, beforeRows, beforeCmds)
		if err != nil {
			return tierOutcome{}, err
		}
		out := tierOutcomeFromSignals(tier, e.d.Runs.Count(task.ID)-beforeCmds, len(newRows))
		out.NewAssets = e.cloudCorrelateNewEvidence(ctx, task, newRows, exploitSel)
		return out, nil
	}

	d := reconDeps{
		Store:     e.d.Store,
		Surface:   task.Surface,
		Grader:    newLLMReconGrader(e.d.Model, e.d.Cfg),
		RunTier:   runTier,
		Backstop:  defaultReconBackstop(),
		Now:       time.Now,
		TaskIDFor: func(string) string { return task.ID },
	}
	if e.d.RC != nil {
		d.Selector = newKBReconSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}
	res, err := ReconLoop(ctx, d, reconSeeds(task.Target), task.ID)
	if err != nil {
		return "", err
	}
	return reconSummary(task, res), nil
}

func (e cloudExecutor) cloudCorrelateNewEvidence(ctx context.Context, task engagement.Task, newRows []engagement.EvidenceRow, sel exploitSelector) []string {
	// Scope pre-prune for discovered-asset recursion. KEEP (user scope decision:
	// exec-time scope + resolve-and-pin survive the gate reduction); it reads the
	// retained scope seam. A nil scope skips the filter (defense-in-depth pre-prune,
	// not the sole control).
	var scope *secgate.Scope
	if e.d.Gate != nil {
		scope = e.d.Gate.Scope
	}
	// auditFn writes the shared "corpus-coverage-gap" audit row for a coverage-gap
	// candidate (finalizeCandidate / groundCandidate call it), so every cloud
	// detector surfaces a gap through the one shared audit path.
	auditFn := func(action, detail string) { _ = e.d.Store.Audit("correlate", action, detail) }
	assetSeen := map[string]bool{}
	candSeen := map[string]bool{}
	var newAssets []string
	var candidates []engagement.Task
	for _, r := range newRows {
		prov := Provenance{TaskID: task.ID, EvidenceID: r.ID}
		for _, a := range parseAssets(prov, r.Quote) {
			if a.Host == "" || assetSeen[a.Host] {
				continue
			}
			if scope != nil && !scope.InScope(a.Host) {
				continue
			}
			assetSeen[a.Host] = true
			newAssets = append(newAssets, a.Host)
		}
		// Shared service+version correlation under the one citation bar (mirrors
		// genericExecutor.correlateNewEvidence): catalog match -> finalizeCandidate;
		// non-catalog -> emit only when the selector names a technique AND a citation
		// grounds it.
		for _, svc := range parseServices(prov, r.Quote) {
			cand, inCatalog := correlateService(svc)
			var tech string
			var cit engagement.Citation
			if sel != nil && svc.Prov.valid() {
				tech, cit = sel(ctx, svc)
			}
			if !inCatalog {
				if tech == "" || cit.Source == "" {
					continue
				}
				cand = candidateTask(svc, tech)
				cand.Citation = cit
			} else {
				if tech != "" && cit.Source != "" {
					cand.Objective = cand.Objective + "; technique: " + tech
				}
				cand = finalizeCandidate(cand, cit, auditFn,
					fmt.Sprintf("%s product=%q ver=%q reason=no-accepted-citation", cand.ID, svc.Product, svc.Version))
			}
			if candSeen[cand.ID] {
				continue
			}
			candSeen[cand.ID] = true
			candidates = append(candidates, cand)
		}

		for _, hit := range cloudFindingHits(prov, r.Quote, task.Surface) {
			cand := groundCandidate(ctx, e.d.RC, e.d.Cfg, auditFn, hit.Task, hit.Query, hit.Term)
			if candSeen[cand.ID] {
				continue
			}
			candSeen[cand.ID] = true
			candidates = append(candidates, cand)
		}
		// Business-logic gaps (shared deterministic detector), grounded under the same
		// bar via groundCandidate.
		for _, hit := range logicGapHits(prov, r.Quote) {
			cand := groundCandidate(ctx, e.d.RC, e.d.Cfg, auditFn, hit.Task, hit.Query, hit.Term)
			if candSeen[cand.ID] {
				continue
			}
			candSeen[cand.ID] = true
			candidates = append(candidates, cand)
		}
	}
	if len(candidates) > 0 {
		if _, err := e.d.Store.Apply(engagement.Delta{Kind: "correlate", Detail: task.ID, Upserts: candidates}); err != nil {
			_ = e.d.Store.Audit("correlate", "apply-failed", err.Error())
		}
	}
	return newAssets
}

type cloudFindingRule struct {
	key       string
	objective string
	skill     string
	query     string
	term      string
	re        *regexp.Regexp
	phrases   []string
}

// cloudFindingRules are evaluated in this fixed order, so a quote that trips
// several yields candidates in a stable sequence. The matchers key on concrete
// disclosure markers in real tool output, not on the probe itself: leaked IMDS
// role credentials (AWS access-key-id format, or an OAuth bearer token from a
// metadata token endpoint), an anonymously listable storage bucket/container, a
// wildcard IAM policy, and an exposed IAM privilege-escalation primitive.
var cloudFindingRules = []cloudFindingRule{
	{
		key:       "imds-aws-creds",
		objective: "cloud metadata credential exposure (AWS IMDS role credentials leaked)",
		skill:     "offensive-cloud",
		query:     "AWS EC2 instance metadata IMDS role credential theft 169.254.169.254",
		term:      "imds",
		// AWS access key id format: AKIA (long-term) or ASIA (STS/temporary) plus 16
		// uppercase alphanumerics. Strong, specific marker of leaked credentials.
		re: regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
	},
	{
		key:       "imds-oauth-token",
		objective: "cloud metadata credential exposure (OAuth access token leaked from instance metadata)",
		skill:     "offensive-cloud",
		query:     "cloud instance metadata OAuth access token theft managed identity service account",
		term:      "metadata",
		// GCP/Azure metadata token endpoints return an OAuth bearer token as
		// {"access_token": "...", ...}. The JSON key is the disclosure marker.
		re: regexp.MustCompile(`(?i)"access_token"\s*:`),
	},
	{
		key:       "storage-exposure",
		objective: "cloud storage exposure (anonymously listable bucket/container contents)",
		skill:     "offensive-cloud",
		query:     "cloud storage bucket container public anonymous listing exposure S3 GCS Azure Blob",
		term:      "storage",
		// S3 ListBucketResult XML, GCS objects JSON, and Azure Blob EnumerationResults
		// all indicate a successful anonymous listing (not an AccessDenied).
		phrases: []string{"listbucketresult", "storage#objects", "storage#bucket", "enumerationresults", "<blobtype>"},
	},
	{
		key:       "iam-wildcard",
		objective: "cloud IAM misconfiguration (wildcard action/principal/resource in policy)",
		skill:     "offensive-cloud",
		query:     "cloud IAM policy misconfiguration wildcard action principal resource overly permissive",
		term:      "iam",
		re:        regexp.MustCompile(`(?i)"(action|principal|resource)"\s*:\s*"\*"`),
	},
	{
		key:       "iam-privesc-primitive",
		objective: "cloud IAM privilege-escalation primitive exposed",
		skill:     "offensive-cloud",
		query:     "cloud IAM privilege escalation PassRole token creator role assignment abuse",
		term:      "iam",
		phrases:   []string{"iam:passrole", "serviceaccounttokencreator", "user access administrator"},
	},
}

// cloudFindingHit is one fast-path table hit: the code-derived UNARMED candidate the
// rule implies, paired with the corpus grounding query and the distinctive service
// term acceptCitation must find. It mirrors logicGapHit so cloudCorrelateNewEvidence
// grounds every cloud finding through the shared groundCandidate - an accepted,
// service-specific citation makes it actionable; none makes it a non-actionable
// coverage-gap (no silent drop). The candidate's Citation / Status / CoverageGap are
// set by groundCandidate -> finalizeCandidate, not here.
type cloudFindingHit struct {
	Task  engagement.Task
	Query string
	Term  string
}

func cloudFindingHits(prov Provenance, quote string, surface engagement.Surface) []cloudFindingHit {
	if !prov.valid() {
		return nil
	}
	lower := strings.ToLower(quote)
	var out []cloudFindingHit
	for _, rule := range cloudFindingRules {
		if !rule.matches(quote, lower) {
			continue
		}
		id := "cloud-" + rule.key + "-" + prov.TaskID + "-" + strconv.FormatInt(prov.EvidenceID, 10)
		out = append(out, cloudFindingHit{
			Task: engagement.Task{
				ID:        id,
				Kind:      "exploit",
				Objective: rule.objective + "; technique via " + rule.skill,
				Status:    engagement.StatusTodo,
				Phase:     engagement.PhaseExploit,
				Surface:   surface,
				Armed:     false,
				BasisIDs:  []string{prov.TaskID},
			},
			Query: rule.query,
			Term:  rule.term,
		})
	}
	return out
}

// matches reports whether this rule fires on the quote. A regex rule tests the raw
// quote (its own (?i) handles case); a phrase rule tests the lowercased quote.
func (r cloudFindingRule) matches(quote, lower string) bool {
	if r.re != nil {
		return r.re.MatchString(quote)
	}
	for _, p := range r.phrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
