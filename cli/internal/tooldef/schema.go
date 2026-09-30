// Package tooldef builds JSON-Schema objects from Go structs for tool definitions.
package tooldef

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// maxDepth bounds recursion so a self-referential struct returns an error.
const maxDepth = 10

// SchemaFor returns a JSON-Schema object for a struct value or a pointer to one.
// Property names come from the json tag (else the Go field name). Fields tagged
// json:"-" and unexported fields are skipped. A desc tag becomes the property
// description. A field is required unless its json tag has omitempty.
func SchemaFor(v any) (map[string]any, error) {
	t := reflect.TypeOf(v)
	if t == nil {
		return nil, fmt.Errorf("tooldef: nil input")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("tooldef: want struct or pointer to struct, got %s", t.Kind())
	}
	return structSchema(t, 0)
}

func structSchema(t reflect.Type, depth int) (map[string]any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("tooldef: %s nests deeper than %d levels", t, maxDepth)
	}
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, omit, skip := parseJSONTag(f)
		if skip {
			continue
		}
		prop, err := typeSchema(f.Type, depth+1)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", f.Name, err)
		}
		if d := f.Tag.Get("desc"); d != "" {
			prop["description"] = d
		}
		props[name] = prop
		if !omit {
			required = append(required, name)
		}
	}
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		schema["required"] = required
	}
	return schema, nil
}

func typeSchema(t reflect.Type, depth int) (map[string]any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}, nil
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}, nil
	case reflect.Slice, reflect.Array:
		items, err := typeSchema(t.Elem(), depth+1)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case reflect.Map:
		return map[string]any{"type": "object"}, nil
	case reflect.Struct:
		return structSchema(t, depth)
	}
	return nil, fmt.Errorf("unsupported kind %s", t.Kind())
}

// parseJSONTag returns the property name, whether omitempty is set, and whether
// the field is skipped (json:"-").
func parseJSONTag(f reflect.StructField) (name string, omitempty, skip bool) {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name, false, false
	}
	if tag == "-" {
		return "", false, true
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = f.Name
	}
	for _, opt := range parts[1:] {
		if opt == "omitempty" {
			omitempty = true
		}
	}
	return name, omitempty, false
}
