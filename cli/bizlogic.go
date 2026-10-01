package main

import (
	"regexp"
	"strconv"
	"strings"

	"blkchain/cli/internal/engagement"
)

type logicGapRule struct {
	key       string
	objective string
	skill     string
	term      string
	re        *regexp.Regexp // nil means use the phrase matcher
	phrases   []string       // lowercased substrings; any match triggers the rule
}

// logicGapRules are evaluated in this fixed order, so a quote that trips several
// yields candidates in a stable sequence. The regexes are anchored on word or
// path boundaries so a longer token (opensshconfig, /administrator, uuid=) does
// not false-match a shorter indicator.
var logicGapRules = []logicGapRule{
	{
		key:       "idor",
		objective: "IDOR / insecure direct object reference",
		skill:     "offensive-idor",
		term:      "idor",
		re:        regexp.MustCompile(`(?i)\b(id|uid|user_id|account_id|order_id|doc_id|objectid)=\d+`),
	},
	{
		key:       "force-browse",
		objective: "missing function-level access control (force-browse to a privileged path)",
		skill:     "offensive-business-logic",
		term:      "forced browsing",
		re:        regexp.MustCompile(`(?i)/(admin|manage|internal|actuator|console|debug)([/?#"'\s]|$)`),
	},
	{
		key:       "price-tamper",
		objective: "price/quantity parameter tampering",
		skill:     "offensive-parameter-pollution",
		term:      "parameter tampering",
		re:        regexp.MustCompile(`(?i)\b(price|amount|cost|qty|quantity|total)=\d`),
	},
	{
		key:       "workflow",
		objective: "workflow / state-machine step abuse",
		skill:     "offensive-business-logic",
		term:      "business logic",
		re:        regexp.MustCompile(`(?i)\b(step|stage|state|next)=`),
	},
	{
		key:       "limit-bypass",
		objective: "quota / one-per-customer limit bypass (race-prone)",
		skill:     "offensive-race-condition",
		term:      "race condition",
		phrases:   []string{"one per customer", "limit reached", "coupon", "voucher", "promo code", "redeem"},
	},
}

type logicGapHit struct {
	Task  engagement.Task
	Query string
	Term  string
}

// logicGapHits scans one verbatim evidence quote and returns the matched
// logic-gap candidates, each paired with its grounding query (the rule skill).
// It returns nil for invalid provenance or no match. correlateLogicGaps is the
// Task-only wrapper for callers that do not ground.
func logicGapHits(prov Provenance, quote string) []logicGapHit {
	if !prov.valid() {
		return nil
	}
	lower := strings.ToLower(quote)
	var out []logicGapHit
	for _, rule := range logicGapRules {
		if !rule.matches(quote, lower) {
			continue
		}
		id := "bizlogic-" + rule.key + "-" + prov.TaskID + "-" + strconv.FormatInt(prov.EvidenceID, 10)
		out = append(out, logicGapHit{
			Task: engagement.Task{
				ID:        id,
				Kind:      "exploit",
				Objective: rule.objective + "; technique via " + rule.skill,
				Status:    engagement.StatusTodo,
				Phase:     engagement.PhaseExploit,
				Surface:   engagement.SurfaceWeb,
				Armed:     false,
				BasisIDs:  []string{prov.TaskID},
			},
			Query: rule.skill + " " + rule.objective,
			Term:  rule.term,
		})
	}
	return out
}

// correlateLogicGaps scans one verbatim evidence quote for business-logic gap
// indicators and returns the UNARMED exploit candidates they imply, in rule
// order, one candidate per matched rule (deduped per rule). It returns nil when
// the provenance is invalid (no candidate without a verified evidence-quote id)
// or no indicator matches. The gate enforces arm + per-action confirm; this only
// plans the candidate. Grounding/coverage-gap handling is applied by the caller
// (see logicGapHits + correlateNewEvidence).
func correlateLogicGaps(prov Provenance, quote string) []engagement.Task {
	hits := logicGapHits(prov, quote)
	if hits == nil {
		return nil
	}
	out := make([]engagement.Task, len(hits))
	for i, h := range hits {
		out[i] = h.Task
	}
	return out
}

// matches reports whether this rule fires on the quote. A regex rule tests the
// raw quote (its own (?i) handles case); a phrase rule tests the lowercased quote.
func (r logicGapRule) matches(quote, lower string) bool {
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
