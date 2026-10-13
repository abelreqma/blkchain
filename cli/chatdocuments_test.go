package main

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chatOfficeFixture(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestChatFileReadsNotebookAndOfficeDocuments(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]struct {
		data []byte
		want string
	}{
		"analysis.ipynb": {[]byte(`{"cells":[{"cell_type":"markdown","source":["Heading\n","Detail"],"outputs":[]},{"cell_type":"code","source":["print(1)"],"outputs":[{"text":["1\n"]}]}]}`), "3|Detail"},
		"report.docx": {chatOfficeFixture(t, map[string]string{
			"word/document.xml": `<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>First paragraph</w:t></w:r></w:p><w:p><w:r><w:t>Second paragraph</w:t></w:r></w:p></w:body></w:document>`,
		}), "Second paragraph"},
		"table.xlsx": {chatOfficeFixture(t, map[string]string{
			"xl/sharedStrings.xml":     `<sst><si><t>name</t></si><si><t>Ada</t></si></sst>`,
			"xl/worksheets/sheet1.xml": `<worksheet><sheetData><row><c t="s"><v>0</v></c><c t="s"><v>1</v></c></row></sheetData></worksheet>`,
		}), "name\tAda"},
	}
	tool := newChatFileReadTool(root)
	for name, fixture := range fixtures {
		if err := os.WriteFile(filepath.Join(root, name), fixture.data, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := tool.Call(context.Background(), `{"path":"`+name+`"}`)
		if err != nil || !strings.Contains(out, fixture.want) {
			t.Errorf("%s extraction: out=%q err=%v", name, out, err)
		}
	}
	search := newChatFileSearchTool(root)
	if out, err := search.Call(context.Background(), `{"pattern":"Ada"}`); err != nil || !strings.Contains(out, "table.xlsx") {
		t.Fatalf("document search failed: out=%q err=%v", out, err)
	}
	write := newChatFileWriteTool(root)
	if out, _ := write.Call(context.Background(), `{"path":"report.docx","content":"replacement"}`); !strings.Contains(out, "read-only") {
		t.Fatalf("binary document write accepted: %q", out)
	}
	patch := newChatFilePatchTool(root)
	if out, _ := patch.Call(context.Background(), `{"path":"report.docx","old":"First","new":"Other"}`); !strings.Contains(out, "read-only") {
		t.Fatalf("binary document patch accepted: %q", out)
	}
}

func TestChatDocumentExtractionBoundsArchiveExpansion(t *testing.T) {
	data := chatOfficeFixture(t, map[string]string{"word/document.xml": strings.Repeat("A", chatFileMaxBytes+1)})
	if _, err := chatDocumentText("bomb.docx", data); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized archive entry accepted: %v", err)
	}
}
