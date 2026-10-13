package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
)

func TestChatFileToolsUseAnEmptyPersistentSandbox(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	project := t.TempDir()
	t.Chdir(project)
	if err := os.WriteFile("host.txt", []byte("host-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("sandbox did not start empty: entries=%v err=%v", entries, err)
	}
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Work with notes.txt", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	call := func(name, args string) string {
		t.Helper()
		tool, ok := reg.Get(name)
		if !ok {
			switch name {
			case "file_write":
				tool = newChatFileWriteTool(root)
			case "file_patch":
				tool = newChatFilePatchTool(root)
			default:
				t.Fatalf("missing %s", name)
			}
		}
		out, err := tool.Call(context.Background(), args)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := call("file_read", `{"path":"host.txt"}`); strings.Contains(got, "host-only") {
		t.Fatalf("host file appeared in empty sandbox: %q", got)
	}
	if got := call("file_write", `{"path":"notes.txt","content":"alpha\nbeta\n"}`); !strings.Contains(got, "saved") {
		t.Fatalf("create failed: %q", got)
	}
	if got := call("file_read", `{"path":"notes.txt","offset":2,"limit":1}`); !strings.Contains(got, "2|beta") || strings.Contains(got, "1|alpha") {
		t.Fatalf("paginated read failed: %q", got)
	}
	if got := call("file_search", `{"pattern":"beta"}`); !strings.Contains(got, "notes.txt:2:beta") {
		t.Fatalf("content search failed: %q", got)
	}
	if got := call("file_search", `{"pattern":"notes[.]txt","mode":"name"}`); !strings.Contains(got, "notes.txt") {
		t.Fatalf("name search failed: %q", got)
	}
	if got := call("file_write", `{"path":"notes.txt","content":"blind overwrite"}`); !strings.Contains(got, "requires expected_sha256") {
		t.Fatalf("blind overwrite accepted: %q", got)
	}
	if got := call("file_patch", `{"path":"notes.txt","old":"beta","new":"gamma"}`); !strings.Contains(got, "line 2") {
		t.Fatalf("patch failed: %q", got)
	}
	old := sha256.Sum256([]byte("alpha\ngamma\n"))
	args := `{"path":"notes.txt","content":"replaced","expected_sha256":"` + hex.EncodeToString(old[:]) + `"}`
	if got := call("file_write", args); !strings.Contains(got, "saved") {
		t.Fatalf("checked replacement failed: %q", got)
	}
	if data, err := os.ReadFile(filepath.Join(root, "notes.txt")); err != nil || string(data) != "replaced" {
		t.Fatalf("sandbox content = %q, err=%v", data, err)
	}
	if data, err := os.ReadFile("host.txt"); err != nil || string(data) != "host-only" {
		t.Fatalf("host file changed: %q, err=%v", data, err)
	}
	if again, err := chatWorkspaceRoot(""); err != nil || again != root {
		t.Fatalf("sandbox changed across turns: %q, err=%v", again, err)
	}
}

func TestChatFileToolsKeepPathsInsideWorkspace(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(outside, []byte("private-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("hidden-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".env", filepath.Join(root, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../private.txt", outside, "escape.txt", "alias.txt", ".env"} {
		if data, err := chatReadFile(root, path); err == nil || strings.Contains(string(data), "private-marker") {
			t.Errorf("read escaped %q: data=%q err=%v", path, data, err)
		}
		if err := chatWriteFile(root, path, []byte("modified"), ""); err == nil {
			t.Errorf("write escaped %q", path)
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "private-marker" {
		t.Fatalf("outside file changed: %q, err=%v", data, err)
	}
	tool := newChatFileSearchTool(root)
	if out, err := tool.Call(context.Background(), `{"pattern":"hidden-marker"}`); err != nil || !strings.Contains(out, "no matches") {
		t.Fatalf("search exposed hidden file: out=%q err=%v", out, err)
	}
}

func TestChatFileReadCapsOutputAndAdvancesOffset(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "long.txt"), []byte(strings.Repeat("a", 900)+"\n"+strings.Repeat("b", 900)), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := newChatFileReadTool(root)
	out, err := tool.Call(context.Background(), `{"path":"long.txt","limit":1}`)
	if err != nil || !strings.Contains(out, "next_offset=2") || !strings.Contains(out, "1|aaa") || strings.Contains(out, "2|bbb") {
		t.Fatalf("pagination failed: out=%q err=%v", out, err)
	}
	if err := os.WriteFile(filepath.Join(root, "long.txt"), []byte(strings.Repeat("x", chatFileOutputBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(context.Background(), `{"path":"long.txt"}`)
	if err != nil || !strings.Contains(out, "line exceeds the output limit") {
		t.Fatalf("oversized line was returned: out=%q err=%v", out, err)
	}
}

func TestChatFileReadsUTF16AndWritesUTF8(t *testing.T) {
	root := t.TempDir()
	raw := []byte{0xff, 0xfe, 'a', 0, 'l', 0, 'p', 0, 'h', 0, 'a', 0}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tool := newChatFileReadTool(root)
	out, err := tool.Call(context.Background(), `{"path":"notes.txt"}`)
	digest := sha256.Sum256(raw)
	if err != nil || !strings.Contains(out, "1|alpha") || !strings.Contains(out, "encoding=utf-16le") || !strings.Contains(out, hex.EncodeToString(digest[:])) {
		t.Fatalf("UTF-16 read failed: out=%q err=%v", out, err)
	}
	patch := newChatFilePatchTool(root)
	out, err = patch.Call(context.Background(), `{"path":"notes.txt","old":"alpha","new":"beta"}`)
	if err != nil || !strings.Contains(out, "updated") {
		t.Fatalf("UTF-16 patch failed: out=%q err=%v", out, err)
	}
	got, err := os.ReadFile(filepath.Join(root, "notes.txt"))
	if err != nil || string(got) != "beta" {
		t.Fatalf("patched text was not UTF-8: %q err=%v", got, err)
	}
	if err := os.WriteFile(filepath.Join(root, "big-endian.txt"), []byte{0, 'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o'}, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(context.Background(), `{"path":"big-endian.txt"}`)
	if err != nil || !strings.Contains(out, "encoding=utf-16be") || !strings.Contains(out, "hello") {
		t.Fatalf("UTF-16BE heuristic failed: out=%q err=%v", out, err)
	}
}
