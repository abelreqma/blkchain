package structgen

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/tmc/langchaingo/llms/openai"
)

func (s Schema) ResponseFormat() (*openai.ResponseFormat, error) {
	property, err := schemaProperty(reflect.TypeOf(s.newTarget()))
	if err != nil {
		return nil, err
	}
	return &openai.ResponseFormat{Type: "json_schema", JSONSchema: &openai.ResponseFormatJSONSchema{
		Name: s.Name, Strict: true, Schema: property,
	}}, nil
}

func schemaProperty(t reflect.Type) (*openai.ResponseFormatJSONSchemaProperty, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	p := &openai.ResponseFormatJSONSchemaProperty{}
	switch t.Kind() {
	case reflect.Struct:
		p.Type = "object"
		p.Properties = map[string]*openai.ResponseFormatJSONSchemaProperty{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if f.PkgPath != "" || name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			field, err := schemaProperty(f.Type)
			if err != nil {
				return nil, err
			}
			var values []string
			switch name {
			case "asset_type":
				values = assetTypes
			case "severity":
				values = severities
				if t.Name() == "Weakness" {
					values = append([]string{""}, values...)
				}
			case "assessment_type":
				values = assessmentTypes
			case "platform":
				values = append([]string{""}, platforms...)
			case "exploitability":
				values = append([]string{""}, exploitability...)
			case "type":
				if t.Name() == "Indicator" {
					values = iocTypes
				}
			}
			for _, value := range values {
				field.Enum = append(field.Enum, value)
			}
			p.Properties[name] = field
			p.Required = append(p.Required, name)
		}
	case reflect.Array, reflect.Slice:
		p.Type = "array"
		var err error
		p.Items, err = schemaProperty(t.Elem())
		if err != nil {
			return nil, err
		}
	case reflect.String:
		p.Type = "string"
	case reflect.Bool:
		p.Type = "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p.Type = "integer"
	case reflect.Float32, reflect.Float64:
		p.Type = "number"
	default:
		return nil, fmt.Errorf("unsupported structured field type %s", t.Kind())
	}
	return p, nil
}
