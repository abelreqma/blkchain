package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

// roewiring_test.go pins the RoE surface against the behavior behind it: that the
// generated template documents what the parser accepts, that the parser's own error
// names every section it accepts, and that a bound the worker enforces is enforced
// here too rather than at exec time.

// The template is the operator's starting point, so every section it emits must be
// one the parser accepts, and the template must itself parse.
func TestTemplateSectionsAreAllParserSections(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader(roeTemplate))
	if err != nil {
		t.Fatalf("the generated template must parse: %v", err)
	}
	if roe.Scope == nil {
		t.Fatal("the template must yield a scope")
	}
	emitted := map[string]bool{}
	for _, line := range strings.Split(roeTemplate, "\n") {
		h, level, ok := headingText(strings.TrimSpace(line))
		if !ok || level == 1 {
			continue
		}
		if !isKnownSection(normalizeSection(h)) {
			t.Errorf("the template emits section %q, which the parser rejects", h)
		}
		emitted[normalizeSection(h)] = true
	}
	// And the other direction: the template is the default policy an operator is
	// handed, so a section the parser accepts and the unrecognized-heading error
	// advertises must appear there with its syntax, not be left to be discovered.
	for _, name := range roeSections {
		if !emitted[normalizeSection(name)] {
			t.Errorf("the parser accepts section %q but the template does not document it", name)
		}
	}
}

// The template's guidance for the optional sections has to be syntax an operator can
// copy. Each example is uncommented into a policy and must parse.
func TestTemplateOptionalSectionExamplesParse(t *testing.T) {
	for _, tc := range []struct{ section, entry string }{
		{"Denied Actions", "api-write"},
		{"Denied Commands", "binary: nikto"},
		{"Denied Commands", "argument: curl --upload-file"},
		{"Resource Caps", "max_commands: 500"},
		{"Resource Caps", "wall_seconds: 7200"},
		{"Resource Caps", "parallel: 1"},
		{"Runner", "id: isolated-worker"},
	} {
		t.Run(tc.section+" "+tc.entry, func(t *testing.T) {
			filled := strings.Replace(roeTemplate, "## In Scope\n", "## In Scope\n192.0.2.1\n", 1)
			filled = strings.Replace(filled, "## "+tc.section+"\n", "## "+tc.section+"\n"+tc.entry+"\n", 1)
			if _, err := ParseRoE(strings.NewReader(filled)); err != nil {
				t.Errorf("the template documents %q under %s, but it does not parse: %v", tc.entry, tc.section, err)
			}
		})
	}
}

// A runner image must be pinned by digest, which the template states. A tag is
// refused, so the guidance is not merely advisory.
func TestTemplateRunnerImageMustBePinned(t *testing.T) {
	withImage := func(image string) error {
		filled := strings.Replace(roeTemplate, "## In Scope\n", "## In Scope\n192.0.2.1\n", 1)
		filled = strings.Replace(filled, "## Runner\n", "## Runner\nimage: "+image+"\n", 1)
		_, err := ParseRoE(strings.NewReader(filled))
		return err
	}
	if err := withImage("dhi.io/qdrant@sha256:" + strings.Repeat("a", 64)); err != nil {
		t.Errorf("a digest-pinned image must parse: %v", err)
	}
	if err := withImage("dhi.io/qdrant:latest"); err == nil {
		t.Error("the template says a tag is refused; it parsed")
	}
}

// The unrecognized-heading error has to name every section the parser accepts. It
// previously named seven of twelve and told an operator that Allowed Actions, a
// section the template itself emits, was not expected.
func TestUnrecognizedSectionErrorNamesEveryAcceptedSection(t *testing.T) {
	_, err := ParseRoE(strings.NewReader("# Rules of Engagement\n\n## Not A Section\nx\n"))
	if err == nil {
		t.Fatal("an unknown heading must be a parse error")
	}
	for _, name := range roeSections {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error omits the accepted section %q: %s", name, err)
		}
		if !isKnownSection(normalizeSection(name)) {
			t.Errorf("roeSections lists %q but isKnownSection rejects it", name)
		}
	}
}

// Each listed section is accepted as a heading, so the list cannot name one the
// parser would refuse.
func TestEveryListedSectionParses(t *testing.T) {
	for _, name := range roeSections {
		if _, err := ParseRoE(strings.NewReader("# Rules of Engagement\n\n## " + name + "\n")); err != nil {
			t.Errorf("section %q is listed but does not parse: %v", name, err)
		}
	}
}

// An oversized env declaration is refused at parse, not at the first command. The
// launcher rejects the request outright, so without this an engagement would start
// and every command would fail with the launcher's message.
func TestFootholdEnvDeclarationIsBounded(t *testing.T) {
	names := make([]string, secgate.FootholdEnvCap)
	for i := range names {
		names[i] = "N" + strconv.Itoa(i)
	}
	atCap := "10.0.0.9 transport=command env=" + strings.Join(names, ",") + " exec=sh -c"
	f, err := secgate.ParseFoothold(atCap)
	if err != nil {
		t.Fatalf("exactly the cap must be accepted: %v", err)
	}
	if len(f.Env) != secgate.FootholdEnvCap {
		t.Errorf("parsed %d names, want %d", len(f.Env), secgate.FootholdEnvCap)
	}

	overCap := "10.0.0.9 transport=command env=" + strings.Join(append(names, "ONEMORE"), ",") + " exec=sh -c"
	if _, err := secgate.ParseFoothold(overCap); err == nil {
		t.Error("more than the cap must be refused at parse")
	} else if !strings.Contains(err.Error(), strconv.Itoa(secgate.FootholdEnvCap)) {
		t.Errorf("the refusal should name the cap, got %v", err)
	}
}

// The cap lives in two languages. This reads the shipped launcher and asserts its
// literal bound equals the Go constant, so the two cannot drift.
func TestFootholdEnvCapMatchesTheLauncher(t *testing.T) {
	script, err := engageRunnerFiles.ReadFile("runner/execute.py")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`len\(declared\) > (\d+)`).FindStringSubmatch(string(script))
	if m == nil {
		t.Fatal("the launcher no longer bounds the declared environment with len(declared) > N; keep this test and the constant in step with it")
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if got != secgate.FootholdEnvCap {
		t.Errorf("the launcher bounds declared names at %d, FootholdEnvCap is %d", got, secgate.FootholdEnvCap)
	}
}

// The template's In Scope guidance has to match the scope rule the gate enforces: an
// internal address needs its own explicit entry, and a hostname does not authorize
// the address it resolves to.
func TestTemplateInScopeGuidanceMatchesTheScopeRule(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader(strings.Replace(roeTemplate,
		"## In Scope\n", "## In Scope\nlocalhost\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if roe.Scope.InScope("127.0.0.1") {
		t.Error("the template says a hostname line leaves the address out of scope; it did not")
	}

	roe, err = ParseRoE(strings.NewReader(strings.Replace(roeTemplate,
		"## In Scope\n", "## In Scope\n127.0.0.1\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if !roe.Scope.InScope("127.0.0.1") {
		t.Error("the template says an explicit IP line puts an internal address in scope; it did not")
	}
}

// The template's Autonomous Actions guidance names the accepted classes, so an
// example it gives must parse and a class it calls rejected must not.
func TestTemplateAutonomousActionGuidanceMatchesTheParser(t *testing.T) {
	withEntry := func(entry string) error {
		_, err := ParseRoE(strings.NewReader(strings.Replace(roeTemplate,
			"## In Scope\n", "## In Scope\n192.0.2.1\nlocal\n", 1) + entry + "\n"))
		return err
	}
	for _, ok := range []string{"exploit/network 192.0.2.1", "recon/local local", "post-ex/network 192.0.2.1"} {
		if err := withEntry(ok); err != nil {
			t.Errorf("the template presents %q as accepted, but: %v", ok, err)
		}
	}
	if err := withEntry("recon/network 192.0.2.1"); err == nil {
		t.Error("the template says recon/network is rejected; it parsed")
	}
}
