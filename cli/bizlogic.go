package main

import (
	"regexp"
	"strconv"
	"strings"

	"blkchain/cli/internal/engagement"
)

// logicGapRule is one deterministic indicator: a stable key, a matcher over the
// verbatim quote, a human objective, and the corpus skill domain that advises
// the technique.
type logicGapRule struct {
	key       string
	objective string
	skill     string
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
		re:        regexp.MustCompile(`(?i)\b(id|uid|user_id|account_id|order_id|doc_id|objectid)=\d+`),
	},
	{
		key:       "force-browse",
		objective: "missing function-level access control (force-browse to a privileged path)",
		skill:     "offensive-business-logic",
		re:        regexp.MustCompile(`(?i)/(admin|manage|internal|actuator|console|debug)([/?#"'\s]|$)`),
	},
	{
		key:       "price-tamper",
		objective: "price/quantity parameter tampering",
		skill:     "offensive-parameter-pollution",
		re:        regexp.MustCompile(`(?i)\b(price|amount|cost|qty|quantity|total)=\d`),
	},
	{
		key:       "workflow",
		objective: "workflow / state-machine step abuse",
		skill:     "offensive-business-logic",
		re:        regexp.MustCompile(`(?i)\b(step|stage|state|next)=`),
	},
	{
		key:       "limit-bypass",
		objective: "quota / one-per-customer limit bypass (race-prone)",
		skill:     "offensive-race-condition",
		phrases:   []string{"one per customer", "limit reached", "coupon", "voucher", "promo code", "redeem"},
	},
}

// correlateLogicGaps scans one verbatim evidence quote for business-logic gap
// indicators and returns the UNARMED exploit candidates they imply, in rule
// order, one candidate per matched rule (deduped per rule). It returns nil when
// the provenance is invalid (no candidate without a verified evidence-quote id)
// or no indicator matches. The gate enforces arm + per-action confirm; this only
// plans the candidate.
func correlateLogicGaps(prov Provenance, quote string) []engagement.Task {
	if !prov.valid() {
		return nil
	}
	lower := strings.ToLower(quote)
	var out []engagement.Task
	for _, rule := range logicGapRules {
		if !rule.matches(quote, lower) {
			continue
		}
		id := "bizlogic-" + rule.key + "-" + prov.TaskID + "-" + strconv.FormatInt(prov.EvidenceID, 10)
		out = append(out, engagement.Task{
			ID:        id,
			Kind:      "exploit",
			Objective: rule.objective + "; technique via " + rule.skill,
			Status:    engagement.StatusTodo,
			Phase:     engagement.PhaseExploit,
			Surface:   engagement.SurfaceWeb,
			Armed:     false,
			BasisIDs:  []string{prov.TaskID},
		})
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
