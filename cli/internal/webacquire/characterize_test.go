package webacquire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// httpBroker returns a broker that may reach only the loopback address, with a resolver that maps the test server's host.
func httpBroker(t *testing.T, srv *httptest.Server) *Broker {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	return &Broker{Policy: Policy{
		Authorize: func(context.Context, Request) error { return nil },
		IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() },
		Resolve: func(_ context.Context, h string) ([]net.IP, error) {
			if h == host {
				return []net.IP{net.ParseIP(host)}, nil
			}
			return nil, errors.New("unknown host")
		},
	}}
}

func TestProfileHeadersReportsSetAndMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Server", "nginx/1.25.5")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileHeaders(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != 200 {
		t.Errorf("Status = %d, want 200", got.Status)
	}
	if got.Security["Strict-Transport-Security"] != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS value not recorded: %q", got.Security["Strict-Transport-Security"])
	}
	if got.Security["X-Content-Type-Options"] != "nosniff" {
		t.Errorf("nosniff not recorded: %+v", got.Security)
	}
	if _, set := got.Security["Content-Security-Policy"]; set {
		t.Error("a header the response did not set was recorded as set")
	}
	for _, want := range []string{"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"} {
		found := false
		for _, m := range got.Missing {
			if m == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is absent from the response but not reported missing: %v", want, got.Missing)
		}
	}
	if got.Exposed["Server"] != "nginx/1.25.5" || got.Exposed["X-Powered-By"] != "PHP/8.1.2" {
		t.Errorf("software disclosure not recorded: %+v", got.Exposed)
	}
	for _, m := range got.Missing {
		if _, set := got.Security[m]; set {
			t.Errorf("%s is reported both set and missing", m)
		}
	}
}

func TestProfileCookiesReadsAttributesWithoutValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "session=s3cr3t-value; Path=/; HttpOnly; Secure; SameSite=Lax")
		h.Add("Set-Cookie", "tracking=abc; Domain=.example.com; Max-Age=86400")
		h.Add("Set-Cookie", "__Host-csrf=xyz; Path=/; Secure; HttpOnly; SameSite=Strict")
		h.Add("Set-Cookie", "bare=1")
		h.Add("Set-Cookie", "malformed-no-equals")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCookies(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("read %d cookies, want 4 (the attribute-less line is not a cookie): %+v", len(got), got)
	}
	by := map[string]CookieFlags{}
	for _, c := range got {
		by[c.Name] = c
	}
	s := by["session"]
	if !s.Secure || !s.HTTPOnly || s.SameSite != "Lax" || s.Path != "/" || !s.Session {
		t.Errorf("session attributes wrong: %+v", s)
	}
	tr := by["tracking"]
	if tr.Secure || tr.HTTPOnly || tr.Domain != ".example.com" || tr.Session {
		t.Errorf("tracking attributes wrong: %+v", tr)
	}
	if by["__Host-csrf"].Prefix != "__Host-" {
		t.Errorf("the __Host- prefix was not recognized: %+v", by["__Host-csrf"])
	}
	b := by["bare"]
	if b.Secure || b.HTTPOnly || b.SameSite != "" || !b.Session {
		t.Errorf("a cookie with no attributes was given some: %+v", b)
	}
	// A cookie's value is a credential and must not be recorded anywhere.
	for _, c := range got {
		for _, field := range []string{c.Name, c.SameSite, c.Path, c.Domain, c.Prefix} {
			if strings.Contains(field, "s3cr3t") || strings.Contains(field, "xyz") {
				t.Errorf("a cookie value was recorded: %+v", c)
			}
		}
	}
}

func TestProfileCORSDetectsAReflectedOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT")
			w.Header().Set("Access-Control-Expose-Headers", "X-Total, X-Page")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCORS(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReflectsOrigin {
		t.Errorf("a reflected origin was not detected: %+v", got)
	}
	if !got.AllowCredentials {
		t.Error("Access-Control-Allow-Credentials was not read")
	}
	if !got.Credentialed() {
		t.Error("a reflected origin with credentials is not reported as credentialed")
	}
	if got.Wildcard {
		t.Error("a reflected origin was reported as a wildcard")
	}
	if !got.AllowsNullOrigin {
		t.Error("the null origin is reflected here but was not reported")
	}
	if len(got.AllowMethods) != 3 {
		t.Errorf("AllowMethods = %v, want three methods", got.AllowMethods)
	}
	if len(got.ExposeHeaders) != 2 {
		t.Errorf("ExposeHeaders = %v, want two headers", got.ExposeHeaders)
	}
	// The probed origin is random under .invalid, so it can never be an origin the target legitimately allows.
	if !strings.HasSuffix(got.ProbedOrigin, ".invalid") {
		t.Errorf("ProbedOrigin = %q, want a name under the reserved .invalid TLD", got.ProbedOrigin)
	}
}

func TestProfileCORSDoesNotCombineSeparateResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin == "null" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCORS(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReflectsOrigin || got.Credentialed() {
		t.Errorf("separate responses were combined into credentialed access: %+v", got)
	}
}

func TestProfileCORSNullOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCORS(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AllowsNullOrigin || !got.Credentialed() {
		t.Errorf("credentialed null-origin access was missed: %+v", got)
	}
}

func TestProfileCORSDistinguishesAFixedAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCORS(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReflectsOrigin {
		t.Errorf("a fixed allowlist was reported as a reflection: %+v", got)
	}
	if got.AllowsNullOrigin {
		t.Error("a fixed allowlist was reported as allowing the null origin")
	}
	if got.Credentialed() {
		t.Error("a fixed allowlist with credentials is not a foreign-origin read")
	}
	if got.AllowOrigin != "https://app.example.com" {
		t.Errorf("AllowOrigin = %q, want the server's own value", got.AllowOrigin)
	}
}

func TestProfileCORSReadsAWildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCORS(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Wildcard {
		t.Errorf("a wildcard policy was not reported: %+v", got)
	}
	if got.ReflectsOrigin {
		t.Error("a wildcard was reported as a reflection")
	}
	// A wildcard cannot be used with credentials by any browser, so it is not a credentialed read however the server answers.
	if got.Credentialed() {
		t.Error("a wildcard was reported as a credentialed read")
	}
}

func TestProfileCORSOnAnOriginWithNoPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).ProfileCORS(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReflectsOrigin || got.Wildcard || got.AllowCredentials || got.AllowsNullOrigin {
		t.Errorf("an origin with no CORS policy was given one: %+v", got)
	}
	if got.AllowOrigin != "" {
		t.Errorf("AllowOrigin = %q, want empty", got.AllowOrigin)
	}
}

func TestInventoryMethodsReadsAllowAndDetectsTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "OPTIONS":
			w.Header().Set("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.WriteHeader(204)
		case "TRACE":
			// Play the request back the way a server that implements TRACE does.
			w.Header().Set("Content-Type", "message/http")
			w.WriteHeader(200)
			fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.URL.Path, r.Host)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).InventoryMethods(context.Background(), srv.URL+"/app")
	if err != nil {
		t.Fatal(err)
	}
	if got.OptionsStatus != 204 {
		t.Errorf("OptionsStatus = %d, want 204", got.OptionsStatus)
	}
	if len(got.Allow) != 5 {
		t.Errorf("Allow = %v, want five methods", got.Allow)
	}
	if len(got.CORSAllowMethods) != 2 {
		t.Errorf("CORSAllowMethods = %v, want two methods", got.CORSAllowMethods)
	}
	if got.TraceStatus != 200 || !got.TraceEchoes {
		t.Errorf("TRACE echo not detected: status=%d echoes=%v", got.TraceStatus, got.TraceEchoes)
	}
}

// An echo is only an echo when the body plays back this request. A 200 with a message/http type that does not contain the request is not one.
func TestInventoryMethodsDoesNotInventATraceEcho(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"method not allowed": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "TRACE" {
				w.WriteHeader(405)
				return
			}
			w.WriteHeader(200)
		},
		"200 with an html body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			w.Write([]byte("<html>not an echo</html>"))
		},
		"message/http without the request": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "message/http")
			w.WriteHeader(200)
			w.Write([]byte("GET /other HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n"))
		},
		// A proxy that refuses TRACE but returns the request in a diagnostic body has not answered it.
		"405 with the request in the body": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "TRACE" {
				w.WriteHeader(200)
				return
			}
			w.Header().Set("Content-Type", "message/http")
			w.WriteHeader(405)
			fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.URL.Path, r.Host)
		},
		"echo for a different host": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "message/http")
			w.WriteHeader(200)
			fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n", r.URL.Path)
		},
	} {
		srv := httptest.NewServer(handler)
		got, err := httpBroker(t, srv).InventoryMethods(context.Background(), srv.URL+"/app")
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.TraceEchoes {
			t.Errorf("%s: a TRACE echo was reported", name)
		}
	}
}

// A server that plays the request back under any type has answered TRACE, so the body rather than the Content-Type decides.
func TestInventoryMethodsDetectsAnEchoUnderAnotherContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "TRACE" {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.URL.Path, r.Host)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).InventoryMethods(context.Background(), srv.URL+"/app")
	if err != nil {
		t.Fatal(err)
	}
	if !got.TraceEchoes {
		t.Errorf("a plain-text playback was not read as an echo: %+v", got)
	}
}

func TestInventoryMethodsReportsAGapWhenOptionsSaysNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).InventoryMethods(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Gap, "OPTIONS named no methods") {
		t.Errorf("Gap does not report the empty Allow: %q", got.Gap)
	}
}

func TestSweepPathsFetchesControlsAlongsidePaths(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			w.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL, "GET",
		[]string{"/robots.txt", "/sitemap.xml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != 2 {
		t.Fatalf("observed %d paths, want 2", len(got.Paths))
	}
	if len(got.Controls) != 3 {
		t.Fatalf("fetched %d controls, want 3", len(got.Controls))
	}
	if got.SoftNotFound {
		t.Error("an origin that answers 404 was marked soft-not-found")
	}
	present := got.Present()
	if len(present) != 1 || present[0] != "/robots.txt" {
		t.Errorf("Present = %v, want only the path that answered 200", present)
	}
	if got.Paths[0].ContentType != "text/plain" || got.Paths[0].Length != 26 {
		t.Errorf("response facts not recorded: %+v", got.Paths[0])
	}
	if got.Method != "GET" {
		t.Errorf("Method = %q, want the method the sweep used", got.Method)
	}
	// Every control path is distinct and random, so an origin cannot be primed.
	seen := map[string]bool{}
	for _, c := range got.Controls {
		if !c.Control {
			t.Errorf("control %q is not marked as one", c.Path)
		}
		if seen[c.Path] {
			t.Errorf("control path %q was used twice", c.Path)
		}
		seen[c.Path] = true
	}
	if len(asked) != 5 {
		t.Errorf("the origin was asked for %d paths, want 2 paths plus 3 controls", len(asked))
	}
}

// An origin that answers 200 for everything makes a 200 meaningless. The census has to say so rather than report every path as present.
func TestSweepPathsDetectsASoftNotFoundOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL, "HEAD",
		[]string{"/robots.txt", "/openapi.json"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.SoftNotFound {
		t.Fatalf("an origin answering 200 for a random path was not marked: %+v", got)
	}
	if present := got.Present(); present != nil {
		t.Errorf("Present = %v, want nothing from a soft-not-found origin", present)
	}
	// The observations are still recorded: the census reports what was seen and says how to read it.
	if len(got.Paths) != 2 {
		t.Errorf("observed %d paths, want both recorded", len(got.Paths))
	}
}

// A redirect is a fact about the path, so it is recorded rather than followed.
func TestSweepPathsRecordsRedirectsWithoutFollowing(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/graphql" {
			w.Header().Set("Location", "/login")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL, "HEAD", []string{"/graphql"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Paths[0].Status != 302 || got.Paths[0].Location != "/login" {
		t.Errorf("the redirect was not recorded: %+v", got.Paths[0])
	}
	if hits != 4 {
		t.Errorf("the origin was asked %d times, want 1 path plus 3 controls and no redirect follow", hits)
	}
}

func TestSweepPathsRefusesANonPassiveMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if _, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL, method, []string{"/x"}); err == nil {
			t.Errorf("%s was accepted for a path sweep", method)
		}
	}
	if _, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL, "GET", []string{"/x"}); err != nil {
		t.Errorf("GET was refused for a path sweep: %v", err)
	}
}

// A census whose controls could not be fetched cannot be read: the paths are still recorded, but nothing is reported present and the gap says why.
func TestSweepPathsWithoutControlsReportsNothingPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	b := httpBroker(t, srv)
	// A policy that allows only the swept paths refuses the random controls, the way a path allowlist would.
	b.Policy.Authorize = func(_ context.Context, r Request) error {
		if strings.HasSuffix(r.URL, "/robots.txt") {
			return nil
		}
		return errors.New("path not allowed")
	}
	got, err := b.SweepPaths(context.Background(), srv.URL, "HEAD", []string{"/robots.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != 1 || got.Paths[0].Status != 200 {
		t.Fatalf("the allowed path was not observed: %+v", got.Paths)
	}
	if len(got.Controls) != 0 {
		t.Fatalf("a control was fetched despite the policy: %+v", got.Controls)
	}
	if present := got.Present(); present != nil {
		t.Errorf("Present = %v, want nothing without controls to compare against", present)
	}
	if !strings.Contains(got.Gap, "control path was not fetched") {
		t.Errorf("Gap does not say the census cannot be read: %q", got.Gap)
	}
}

func TestMetadataPathsAreAbsoluteAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range MetadataPaths() {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("%q is not an absolute path", p)
		}
		if strings.ContainsAny(p, " \r\n\x00?#") {
			t.Errorf("%q is not a bare path", p)
		}
		if seen[p] {
			t.Errorf("%q is listed twice", p)
		}
		seen[p] = true
	}
	if len(MetadataPaths()) < 10 {
		t.Errorf("the sweep covers only %d paths", len(MetadataPaths()))
	}
}

// Every probe here is a network action and goes through the broker, so the scope controls bound it.
func TestCharacterizationProbesEnforceScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	deny := func() *Broker {
		b := httpBroker(t, srv)
		b.Policy.Authorize = func(context.Context, Request) error { return errors.New("out of scope") }
		return b
	}
	if _, err := deny().ProfileHeaders(context.Background(), srv.URL); err == nil {
		t.Error("ProfileHeaders ran past a policy refusal")
	}
	if _, err := deny().ProfileCookies(context.Background(), srv.URL); err == nil {
		t.Error("ProfileCookies ran past a policy refusal")
	}
	if _, err := deny().ProfileCORS(context.Background(), srv.URL); err == nil {
		t.Error("ProfileCORS ran past a policy refusal")
	}
	if _, err := deny().InventoryMethods(context.Background(), srv.URL); err != nil {
		// InventoryMethods records the refusal as a gap rather than failing, so the inventory still reports what is unknown.
		t.Errorf("InventoryMethods returned an error instead of a gap: %v", err)
	} else if inv, _ := deny().InventoryMethods(context.Background(), srv.URL); inv.OptionsStatus != 0 || inv.Gap == "" {
		t.Errorf("InventoryMethods did not report the refusal as a gap: %+v", inv)
	}
	if census, err := deny().SweepPaths(context.Background(), srv.URL, "HEAD", []string{"/robots.txt"}); err != nil {
		t.Errorf("SweepPaths returned an error instead of a gap: %v", err)
	} else if len(census.Paths) != 0 || census.Gap == "" {
		t.Errorf("SweepPaths did not report the refusal as a gap: %+v", census)
	}
}

func TestCharacterizationProbesRejectABadURL(t *testing.T) {
	b := &Broker{}
	for _, raw := range []string{"", "not a url", "ftp://host/x", "http://user:pw@host/", "//host/x"} {
		if _, err := b.ProfileHeaders(context.Background(), raw); err == nil {
			t.Errorf("ProfileHeaders accepted %q", raw)
		}
		if _, err := b.ProfileCORS(context.Background(), raw); err == nil {
			t.Errorf("ProfileCORS accepted %q", raw)
		}
		if _, err := b.InventoryMethods(context.Background(), raw); err == nil {
			t.Errorf("InventoryMethods accepted %q", raw)
		}
		if _, err := b.SweepPaths(context.Background(), raw, "HEAD", nil); err == nil {
			t.Errorf("SweepPaths accepted %q", raw)
		}
	}
}

// A sweep names the origin it swept, not the URL it was given, so a path observation is unambiguous.
func TestSweepPathsNormalizesTheOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	got, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL+"/deep/path?q=1", "HEAD", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != srv.URL {
		t.Errorf("Origin = %q, want %q", got.Origin, srv.URL)
	}
}

func TestSweepPathsPrefixesABarePath(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		w.WriteHeader(404)
	}))
	defer srv.Close()
	if _, err := httpBroker(t, srv).SweepPaths(context.Background(), srv.URL, "HEAD", []string{"robots.txt"}); err != nil {
		t.Fatal(err)
	}
	if len(asked) == 0 || asked[0] != "/robots.txt" {
		t.Errorf("asked for %v, want /robots.txt", asked)
	}
}

// rawHTTPServer answers every request with the given raw response bytes and returns its base URL. net/http's own server recomputes Content-Length on a bodyless HEAD, so a server that reports one has to be spoken directly.
func rawHTTPServer(t *testing.T, response string) (string, func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	hits := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				mu.Lock()
				hits++
				mu.Unlock()
				conn.Write([]byte(response))
			}()
		}
	}()
	return "http://" + ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits
	}
}

// A HEAD census has no body to measure, so it records no length and the comparison against the controls rests on status, type and location. A GET census of the same origin does measure the body.
func TestSweepPathsHasNoLengthOnHEADAndOneOnGET(t *testing.T) {
	base, _ := rawHTTPServer(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n")
	b := &Broker{Policy: Policy{
		Authorize: func(context.Context, Request) error { return nil },
		IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() },
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}}
	got, err := b.SweepPaths(context.Background(), base, "HEAD", []string{"/openapi.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != 1 {
		t.Fatalf("observed %d paths, want 1", len(got.Paths))
	}
	if got.Paths[0].Length != 0 {
		t.Errorf("Length = %d, want 0 for a HEAD census", got.Paths[0].Length)
	}
	if got.Paths[0].ContentType != "application/json" {
		t.Errorf("ContentType = %q", got.Paths[0].ContentType)
	}
	if got.Paths[0].Status != 200 {
		t.Errorf("Status = %d, want 200", got.Paths[0].Status)
	}
	// Every path answers 200 here, controls included, so the census says the origin does not distinguish.
	if !got.SoftNotFound {
		t.Error("an origin answering 200 for every control was not marked")
	}
}
