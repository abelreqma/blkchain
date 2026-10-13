package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func chatDocumentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".ipynb":
		return "notebook"
	case ".docx":
		return "docx"
	case ".xlsx":
		return "xlsx"
	}
	return ""
}

func chatDocumentText(name string, data []byte) ([]byte, error) {
	switch chatDocumentType(name) {
	case "notebook":
		return chatNotebookText(data)
	case "docx":
		return chatOfficeText(data, "docx")
	case "xlsx":
		return chatOfficeText(data, "xlsx")
	}
	return nil, fmt.Errorf("unsupported document format")
}

func chatNotebookText(data []byte) ([]byte, error) {
	var notebook struct {
		Cells []struct {
			CellType string          `json:"cell_type"`
			Source   json.RawMessage `json:"source"`
			Outputs  []struct {
				Text json.RawMessage            `json:"text"`
				Data map[string]json.RawMessage `json:"data"`
			} `json:"outputs"`
		} `json:"cells"`
	}
	if err := json.Unmarshal(data, &notebook); err != nil {
		return nil, err
	}
	if len(notebook.Cells) > 1000 {
		return nil, fmt.Errorf("notebook exceeds the cell limit")
	}
	var out strings.Builder
	for i, cell := range notebook.Cells {
		fmt.Fprintf(&out, "## Cell %d (%s)\n", i+1, cell.CellType)
		out.WriteString(chatNotebookField(cell.Source))
		out.WriteByte('\n')
		for _, output := range cell.Outputs {
			text := output.Text
			if len(text) == 0 {
				text = output.Data["text/plain"]
			}
			if len(text) > 0 {
				out.WriteString(chatNotebookField(text))
				out.WriteByte('\n')
			}
		}
		if out.Len() > chatFileMaxBytes {
			return nil, fmt.Errorf("notebook text exceeds the size limit")
		}
	}
	return []byte(out.String()), nil
}

func chatNotebookField(raw json.RawMessage) string {
	var lines []string
	if json.Unmarshal(raw, &lines) == nil {
		return strings.Join(lines, "")
	}
	var text string
	_ = json.Unmarshal(raw, &text)
	return text
}

func chatOfficeText(data []byte, kind string) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if len(archive.File) > 1000 {
		return nil, fmt.Errorf("document archive exceeds the entry limit")
	}
	readTotal := 0
	entry := func(name string) ([]byte, error) {
		for _, file := range archive.File {
			if file.Name != name {
				continue
			}
			if file.UncompressedSize64 > uint64(chatFileMaxBytes-readTotal) {
				return nil, fmt.Errorf("document entry exceeds the size limit")
			}
			reader, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer reader.Close()
			value, err := io.ReadAll(io.LimitReader(reader, int64(chatFileMaxBytes-readTotal+1)))
			if err != nil || len(value) > chatFileMaxBytes-readTotal {
				return nil, fmt.Errorf("document entry exceeds the size limit")
			}
			readTotal += len(value)
			return value, nil
		}
		return nil, fmt.Errorf("document entry %s is missing", name)
	}
	if kind == "docx" {
		body, err := entry("word/document.xml")
		if err != nil {
			return nil, err
		}
		return chatWordXML(body)
	}
	var shared []string
	if body, err := entry("xl/sharedStrings.xml"); err == nil {
		shared, err = chatSharedStrings(body)
		if err != nil {
			return nil, err
		}
	}
	var sheets []string
	for _, file := range archive.File {
		if strings.HasPrefix(file.Name, "xl/worksheets/sheet") && strings.HasSuffix(file.Name, ".xml") {
			sheets = append(sheets, file.Name)
		}
	}
	if len(sheets) == 0 || len(sheets) > 20 {
		return nil, fmt.Errorf("workbook must contain 1 to 20 sheets")
	}
	sort.Strings(sheets)
	var out strings.Builder
	for _, sheet := range sheets {
		body, err := entry(sheet)
		if err != nil {
			return nil, err
		}
		text, err := chatSheetXML(body, shared)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&out, "## %s\n%s\n", filepath.Base(sheet), text)
		if out.Len() > chatFileMaxBytes {
			return nil, fmt.Errorf("workbook text exceeds the size limit")
		}
	}
	return []byte(out.String()), nil
}

func chatWordXML(data []byte) ([]byte, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out strings.Builder
	insideText := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			insideText = value.Name.Local == "t"
			if value.Name.Local == "tab" {
				out.WriteByte('\t')
			}
		case xml.CharData:
			if insideText {
				out.Write(value)
			}
		case xml.EndElement:
			if value.Name.Local == "t" {
				insideText = false
			}
			if value.Name.Local == "p" {
				out.WriteByte('\n')
			}
		}
		if out.Len() > chatFileMaxBytes {
			return nil, fmt.Errorf("document text exceeds the size limit")
		}
	}
	return []byte(out.String()), nil
}

func chatSharedStrings(data []byte) ([]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var values []string
	var current strings.Builder
	total := 0
	insideText := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			insideText = value.Name.Local == "t"
		case xml.CharData:
			if insideText {
				current.Write(value)
			}
		case xml.EndElement:
			if value.Name.Local == "t" {
				insideText = false
			}
			if value.Name.Local == "si" {
				values = append(values, current.String())
				total += current.Len()
				current.Reset()
			}
		}
		if len(values) > 100000 || total+current.Len() > chatFileMaxBytes {
			return nil, fmt.Errorf("shared strings exceed the limit")
		}
	}
	return values, nil
}

func chatSheetXML(data []byte, shared []string) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out strings.Builder
	var cell strings.Builder
	cellType, insideValue := "", false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Local == "c" {
				cellType = ""
				cell.Reset()
				for _, attr := range value.Attr {
					if attr.Name.Local == "t" {
						cellType = attr.Value
					}
				}
			}
			insideValue = value.Name.Local == "v" || value.Name.Local == "t" && cellType == "inlineStr"
		case xml.CharData:
			if insideValue {
				cell.Write(value)
			}
		case xml.EndElement:
			if value.Name.Local == "v" || value.Name.Local == "t" {
				insideValue = false
			}
			if value.Name.Local == "c" {
				text := cell.String()
				if cellType == "s" {
					index, err := strconv.Atoi(text)
					if err != nil || index < 0 || index >= len(shared) {
						return "", fmt.Errorf("invalid shared string index")
					}
					text = shared[index]
				}
				out.WriteString(text)
				out.WriteByte('\t')
			}
			if value.Name.Local == "row" {
				out.WriteByte('\n')
			}
		}
		if out.Len() > chatFileMaxBytes || cell.Len() > chatFileMaxBytes {
			return "", fmt.Errorf("sheet text exceeds the size limit")
		}
	}
	return out.String(), nil
}
