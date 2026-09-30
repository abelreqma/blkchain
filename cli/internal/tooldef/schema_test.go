package tooldef

import (
	"encoding/json"
	"reflect"
	"testing"
)

// jsonEqual compares got against a JSON literal after a marshal round trip.
func jsonEqual(t *testing.T, got map[string]any, want string) {
	t.Helper()
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var g, w any
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("schema mismatch\n got: %s\nwant: %s", b, want)
	}
}

func TestSchemaForFlatStruct(t *testing.T) {
	type args struct {
		Query string `json:"query" desc:"search text"`
		Deep  bool   `json:"deep" desc:"search deeper"`
		Limit int    `json:"limit" desc:"max results"`
		Ratio float64
	}
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, s, `{
		"type":"object",
		"properties":{
			"query":{"type":"string","description":"search text"},
			"deep":{"type":"boolean","description":"search deeper"},
			"limit":{"type":"integer","description":"max results"},
			"Ratio":{"type":"number"}
		},
		"required":["Ratio","deep","limit","query"]
	}`)
	req, ok := s["required"].([]string)
	if !ok {
		t.Fatalf("required is %T, want []string", s["required"])
	}
	if !reflect.DeepEqual(req, []string{"Ratio", "deep", "limit", "query"}) {
		t.Fatalf("required not sorted: %v", req)
	}
}

func TestSchemaForPointerInput(t *testing.T) {
	type args struct {
		Q string `json:"q"`
	}
	s, err := SchemaFor(&args{})
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, s, `{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}`)
}

func TestSchemaForOmitempty(t *testing.T) {
	type args struct {
		A string `json:"a"`
		B string `json:"b,omitempty"`
	}
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, s, `{
		"type":"object",
		"properties":{"a":{"type":"string"},"b":{"type":"string"}},
		"required":["a"]
	}`)
}

func TestSchemaForNoRequiredKeyWhenEmpty(t *testing.T) {
	type args struct {
		A string `json:"a,omitempty"`
	}
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s["required"]; ok {
		t.Fatalf("required key present: %v", s)
	}
}

func TestSchemaForSlice(t *testing.T) {
	type args struct {
		Tags []string `json:"tags" desc:"labels"`
	}
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, s, `{
		"type":"object",
		"properties":{"tags":{"type":"array","items":{"type":"string"},"description":"labels"}},
		"required":["tags"]
	}`)
}

func TestSchemaForNestedStruct(t *testing.T) {
	type inner struct {
		N int    `json:"n"`
		S string `json:"s,omitempty"`
	}
	type args struct {
		In  inner  `json:"in"`
		Ptr *inner `json:"ptr,omitempty"`
	}
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	nested := `{"type":"object","properties":{"n":{"type":"integer"},"s":{"type":"string"}},"required":["n"]}`
	jsonEqual(t, s, `{
		"type":"object",
		"properties":{"in":`+nested+`,"ptr":`+nested+`},
		"required":["in"]
	}`)
}

func TestSchemaForMap(t *testing.T) {
	type args struct {
		M map[string]string `json:"m"`
	}
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, s, `{"type":"object","properties":{"m":{"type":"object"}},"required":["m"]}`)
}

func TestSchemaForSkipsHiddenFields(t *testing.T) {
	type args struct {
		Keep   string `json:"keep"`
		Skip   string `json:"-"`
		hidden string
	}
	_ = args{}.hidden
	s, err := SchemaFor(args{})
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, s, `{"type":"object","properties":{"keep":{"type":"string"}},"required":["keep"]}`)
}

func TestSchemaForErrors(t *testing.T) {
	type withChan struct {
		C chan int `json:"c"`
	}
	type withFunc struct {
		F func() `json:"f"`
	}
	type node struct {
		Next *node `json:"next"`
	}
	cases := map[string]any{
		"string":    "x",
		"int":       3,
		"nil":       nil,
		"chan":      withChan{},
		"func":      withFunc{},
		"recursive": node{},
	}
	for name, v := range cases {
		if _, err := SchemaFor(v); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
