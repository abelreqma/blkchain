package webanalysis

import (
	"context"
	"strings"
	"testing"
)

func input(s string) Input {
	return Input{Unit: SourceUnit{ID: ID("fixture"), URL: "https://app.test/assets/bundle.js", Language: "javascript"}, Source: []byte(s), Role: "reader"}
}
func TestFunctionsParametersWrappersAndShadowing(t *testing.T) {
	src := `const client=axios.create({baseURL:"https://app.test/api",headers:{"Content-Type":"application/json"}});
 function profile(id){return fetch('/api/users/'+id,{headers:{Authorization:token}})}
 function bill(amount){return client.post('/billing',{amount})}
 profile("123");
 function shadow(fetch){fetch('/fabricated')}
 fetch('/api/search?q='+term);
 new WebSocket('wss://app.test/socket');
 fetch('/graphql',{method:'POST',body:JSON.stringify({query:'query User($id: ID!){ user(id:$id){name}}',variables:{id}})});
 `
	out, e := Analyze(context.Background(), input(src))
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]Operation{}
	for _, o := range out.Operations {
		found[o.Path] = o
		if strings.Contains(o.Path, "fabricated") {
			t.Fatal("shadowed fetch fabricated API")
		}
	}
	for _, path := range []string{"/api/users/{id}", "/api/users/123", "/api/billing", "/api/search", "/graphql", "/socket"} {
		if _, ok := found[path]; !ok {
			t.Errorf("missing %s: %+v", path, out.Operations)
		}
	}
	if len(out.Functions) != 3 || len(out.Relationships) == 0 {
		t.Fatalf("missing function/parameter records: %+v", out.Functions)
	}
	if found["/graphql"].GraphQL == "" || len(found["/graphql"].Variables) != 1 {
		t.Fatal("GraphQL variables lost")
	}
	if found["/socket"].Protocol != "websocket" {
		t.Fatal("WebSocket presented as HTTP")
	}
	p := found["/api/billing"].Parameters
	ok := false
	for _, v := range p {
		if v.Field == "body.amount" && v.Expression == "{amount}" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("amount binding lost: %+v", p)
	}
}
func TestMalformedLimitsUnresolvedAndSecretNegatives(t *testing.T) {
	out, e := Analyze(context.Background(), input(`function broken( {; import(foo); fetch(url); const token="0123456789abcdef0123456789abcdef";`))
	if e != nil {
		t.Fatal(e)
	}
	if out.Units[0].Parse != "partial" || len(out.Gaps) == 0 {
		t.Fatal("parser failure not recorded")
	}
	for _, f := range out.Findings {
		if f.Detector == "entropy-context" {
			t.Fatal("hash flagged as entropy credential")
		}
	}
	if _, e = Analyze(context.Background(), input(strings.Repeat("x", MaxSource+1))); e == nil {
		t.Fatal("unbounded source")
	}
	ctx, c := context.WithCancel(context.Background())
	c()
	if _, e = Analyze(ctx, input("fetch('/a')")); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestImportsDeobfuscationAndFeaturePrecision(t *testing.T) {
	out, e := Analyze(context.Background(), input(`import './base.js';import('./lazy.js');const names=['/api/profile'];fetch(names[0]); const decoded=atob('L2FwaS9iaWxsaW5n');fetch(decoded);`))
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Dependencies) < 2 {
		t.Fatal("imports lost")
	}
	for _, s := range []string{"administrator", "admin"} {
		if FeatureTags(s)[0] != "admin" {
			t.Fatal("admin tag missing")
		}
	}
	if FeatureTags("administrative")[0] != "uncategorized" {
		t.Fatal("substring feature tag")
	}
	found := false
	for _, o := range out.Operations {
		if o.Path == "/api/billing" {
			found = true
		}
	}
	if !found {
		t.Fatal("bounded decoded constant lost")
	}
}

func TestXHRDefaultsDestructuringAndQualifiedShadowing(t *testing.T) {
	source := []byte(`const xhr=new XMLHttpRequest();xhr.open('POST','/api/xhr');xhr.setRequestHeader('Content-Type','application/json');xhr.send(JSON.stringify({amount:5}));const client=axios.create({baseURL:'/v2'});client.defaults.baseURL='/v3';client.post('/billing',{amount:3},{headers:{'X-Role':'reader'}});function profile({id}){return fetch('/api/profile/'+id)}profile({id:'42'});function hidden(window){window.fetch('/fake')};`)
	result, e := Analyze(context.Background(), Input{Unit: SourceUnit{ID: ID("extended"), URL: "https://fixture.test/app.js"}, Source: source})
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]Operation{}
	for _, o := range result.Operations {
		seen[o.Path] = o
	}
	for _, p := range []string{"/api/xhr", "/v3/billing", "/api/profile/{id}", "/api/profile/42"} {
		if _, ok := seen[p]; !ok {
			t.Fatalf("missing %s: %v", p, seen)
		}
	}
	if _, ok := seen["/fake"]; ok {
		t.Fatal("qualified shadow fabricated route")
	}
	xhr := seen["/api/xhr"]
	amount, content := false, false
	for _, p := range xhr.Parameters {
		amount = amount || p.Field == "body.amount"
		content = content || p.Field == "header.Content-Type"
	}
	if !amount || !content || xhr.ContentType != "application/json" {
		t.Fatal(xhr)
	}
}

func TestImportedShadowingInterceptorAndBuildTables(t *testing.T) {
	out, e := Analyze(context.Background(), input(`import fetch from './fake.js';import axios from 'axios';const client=axios.create({baseURL:'/old'});client.interceptors.request.use(config=>{config.baseURL='/v4';config.headers={'X-Role':'reader'};return config});client.get('/billing');fetch('/fabricated');__webpack_require__.p='/assets/';__webpack_require__.u=id=>id+'.'+({7:'hash7',8:'hash8'}[id])+'.js';const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=['/assets/lazy.js','/assets/main.js'])))=>i.map(i=>d[i]);`))
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, op := range out.Operations {
		if op.Path == "/fabricated" {
			t.Fatal("import shadowing invented an API")
		}
		if op.Path == "/v4/billing" {
			found = true
			header := false
			for _, p := range op.Parameters {
				header = header || p.Field == "header.X-Role" && p.Expression == "reader"
			}
			if !header {
				t.Fatal("interceptor header missing")
			}
		}
	}
	if !found {
		t.Fatal(out.Operations)
	}
	deps := map[string]bool{}
	for _, d := range out.Dependencies {
		deps[d.URL] = true
	}
	for _, name := range []string{"/assets/7.hash7.js", "/assets/8.hash8.js", "/assets/lazy.js"} {
		if !deps[name] {
			t.Fatalf("missing build reference %s: %v", name, deps)
		}
	}
}

func TestAxiosQueryShapeJoinsObservedRequest(t *testing.T) {
	result, e := Analyze(context.Background(), input(`const c=axios.create({baseURL:'/api'});c.get('/search',{params:{q:'a+b',page:2}});const escaped=decodeURIComponent('a+b');fetch('/api/'+escaped)`))
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, op := range result.Operations {
		if op.Path == "/api/search" {
			observed, e := FromObserved(RequestExample{URL: op.Origin + "/api/search?page=2&q=a%2Bb", Method: "GET", Status: 200})
			if e != nil || !MatchesObserved(op, observed) {
				t.Fatal(op, e)
			}
			found = true
		}
		if op.Path == "/api/a b" {
			t.Fatal("decodeURIComponent incorrectly decoded plus")
		}
	}
	if !found {
		t.Fatal(result.Operations)
	}
}

func TestLexicalBindingsSuppressFabricatedNetworkCalls(t *testing.T) {
	cases := []string{
		`const {fetch}=client; function f(){fetch('/fabricated')} fetch('/fabricated');`,
		`const {request:{fetch}}=client; function f(){fetch('/fabricated')}`,
		`const [fetch]=client; function f(){fetch('/fabricated')}`,
		`const {...fetch}=client; function f(){fetch('/fabricated')}`,
		`try{}catch(fetch){fetch('/fabricated')} fetch('/global');`,
		`for(let fetch of list){fetch('/fabricated')} fetch('/global');`,
		`for(const {fetch} of list){fetch('/fabricated')} fetch('/global');`,
		`for(let fetch=other;condition;step){fetch('/fabricated')} fetch('/global');`,
		`function f(){fetch('/fabricated');if(flag){var fetch=other}} fetch('/global');`,
		`function f(){if(flag){var fetch=other}fetch('/fabricated')} fetch('/global');`,
		`function f(){fetch('/fabricated');for(var fetch of list){}} fetch('/global');`,
		`function f([fetch]){fetch('/fabricated')} fetch('/global');`,
		`function f({nested:{fetch}}){fetch('/fabricated')} fetch('/global');`,
		`(function fetch(){fetch('/fabricated')})();fetch('/global');`,
		`{const fetch=other;fetch('/fabricated')} fetch('/global');`,
		`class fetch{};function f(){fetch('/fabricated')}`,
		`function* f(fetch){fetch('/fabricated')};fetch('/global');`,
		`class A{f(fetch){fetch('/fabricated')}};fetch('/global');`,
		`class A{fetch(){fetch('/global')}};fetch('/global');`,
		`const o={f(){var fetch=local}};fetch('/global');`,
		`function f(){fetch('/global')} const {fetch:local}=client;local('/fabricated');`,
		`fetch('/global');const {fetch:other=fetch}=client;`,
	}
	for _, source := range cases {
		t.Run(source, func(t *testing.T) {
			out, err := Analyze(context.Background(), input(source))
			if err != nil {
				t.Fatal(err)
			}
			global := false
			for _, op := range out.Operations {
				if op.Path == "/fabricated" {
					t.Fatal("shadowed binding fabricated API", op)
				}
				global = global || op.Path == "/global"
			}
			if strings.Contains(source, "'/global'") && !global && out.Units[0].Parse == "ok" {
				t.Fatal("global fetch incorrectly suppressed")
			}
		})
	}
}
func TestUnknownFetchOptionsStayUnresolved(t *testing.T) {
	for _, source := range []string{
		`fetch('/api/change',{...options})`,
		`fetch('/api/change',options)`,
		`fetch('/api/change',{method:'POST',...options})`,
		`fetch('/api/change',{[field]:value})`,
		`fetch('/api/change',{method:'POST',[field]:value})`,
		`fetch('/api/change',{...{...options}})`,
		`fetch('/api/change',{...options,method:'POST'})`,
	} {
		t.Run(source, func(t *testing.T) {
			out, err := Analyze(context.Background(), input(source))
			if err != nil || len(out.Operations) != 1 {
				t.Fatal(out, err)
			}
			op := out.Operations[0]
			if len(op.Unresolved) == 0 || len(out.Gaps) == 0 {
				t.Fatal("unknown options presented as complete", op)
			}
			template, err := CurlTemplate(op)
			if err != nil || template.Replayable {
				t.Fatal("unknown options replayable", template, err)
			}
			if strings.Contains(source, "...options,method:'POST'") {
				if op.Method != "POST" {
					t.Fatal("explicit final method lost")
				}
			} else if op.Method != "UNKNOWN" {
				t.Fatal("runtime method invented", op)
			}
		})
	}
	for _, source := range []string{`fetch('/api/read')`, `fetch('/api/read',null)`, `fetch('/api/read',undefined)`, `const cfg={method:'POST'};fetch('/api/read',{...cfg})`} {
		out, err := Analyze(context.Background(), input(source))
		if err != nil || len(out.Operations) != 1 || len(out.Operations[0].Unresolved) != 0 {
			t.Fatal(source, out, err)
		}
	}
}
