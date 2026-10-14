package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
)

func TestChatTransferRequiresNamedSourceAndNeverOverwrites(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	project := t.TempDir()
	t.Chdir(project)
	if err := os.WriteFile("host.txt", []byte("host content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("secret.txt", []byte("secret content"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Import host.txt into the sandbox", nil, AnswerOpts{requiredAction: "file_import", vantage: vantageLocal})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("file_import")
	if !ok {
		t.Fatal("file_import was not registered")
	}
	if out, err := tool.Call(context.Background(), `{"source":"secret.txt"}`); err != nil || !strings.Contains(out, "must be named") {
		t.Fatalf("unnamed source accepted: out=%q err=%v", out, err)
	}
	if out, err := tool.Call(context.Background(), `{"source":"host.txt"}`); err != nil || !strings.Contains(out, "copied 1") {
		t.Fatalf("import failed: out=%q err=%v", out, err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "host.txt")); err != nil || string(data) != "host content" {
		t.Fatalf("imported file = %q, err=%v", data, err)
	}
	if out, err := tool.Call(context.Background(), `{"source":"host.txt"}`); err != nil || !strings.Contains(out, "expected_sha256") {
		t.Fatalf("import overwrote an existing file: out=%q err=%v", out, err)
	}
	if err := os.WriteFile(filepath.Join(root, "sandbox.txt"), []byte("sandbox content"), 0o600); err != nil {
		t.Fatal(err)
	}
	export, closeExport, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Export sandbox.txt", nil, AnswerOpts{requiredAction: "file_export", vantage: vantageLocal})
	if err != nil {
		t.Fatal(err)
	}
	defer closeExport()
	tool, ok = export.Get("file_export")
	if !ok {
		t.Fatal("file_export was not registered")
	}
	if out, err := tool.Call(context.Background(), `{"source":"sandbox.txt"}`); err != nil || !strings.Contains(out, "copied 1") {
		t.Fatalf("export failed: out=%q err=%v", out, err)
	}
	if data, err := os.ReadFile("sandbox.txt"); err != nil || string(data) != "sandbox content" {
		t.Fatalf("exported file = %q, err=%v", data, err)
	}
}

// TestChatTransferRequiresALocalCaller pins that the transfer tools are
// refused to a caller that is not local. file_import reads this host's working
// directory into the sandbox and file_export writes into it, so a remote caller
// would reach the operator's files through a sandboxed turn. The zero vantage is
// remote, so a surface that does not establish its caller is refused too.
func TestChatTransferRequiresALocalCaller(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	if err := os.WriteFile("host.txt", []byte("host content"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"file_import", "file_export"} {
		for _, v := range []clientVantage{vantageRemote, clientVantage(0)} {
			reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Import host.txt", nil, AnswerOpts{requiredAction: action, vantage: v})
			if err == nil {
				closeTools()
				if _, ok := reg.Get(action); ok {
					t.Fatalf("%s was registered for vantage %v", action, v)
				}
				t.Fatalf("%s for vantage %v returned no error", action, v)
			}
			if !strings.Contains(err.Error(), "local caller") {
				t.Errorf("%s refusal %q must say a local caller is required", action, err)
			}
		}
	}
}

func TestChatDirectoryImportIsAtomicOnInvalidFile(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	if err := os.Mkdir("src", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("src/a.txt", []byte("valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("src/b.bin", make([]byte, chatFileMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chatCopyWorkspace(".", root, "src", "copy"); err == nil {
		t.Fatal("oversized file did not stop directory import")
	}
	if _, err := os.Stat(filepath.Join(root, "copy")); !os.IsNotExist(err) {
		t.Fatalf("partial directory appeared after failed import: %v", err)
	}
	if err := os.Remove("src/b.bin"); err != nil {
		t.Fatal(err)
	}
	if count, err := chatCopyWorkspace(".", root, "src", "copy"); err != nil || count != 1 {
		t.Fatalf("valid directory import: count=%d err=%v", count, err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "copy", "a.txt")); err != nil || string(data) != "valid" {
		t.Fatalf("imported content=%q err=%v", data, err)
	}
}

func TestChatTransferCopiesBinaryAssets(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	asset := []byte{0, 1, 2, 255}
	if err := os.WriteFile("asset.bin", asset, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chatCopyWorkspace(".", root, "asset.bin", "asset.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := chatReadFile(root, "asset.bin"); err == nil {
		t.Fatal("binary asset exposed as model text")
	}
	if _, err := chatCopyWorkspace(root, ".", "asset.bin", "copy.bin"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("copy.bin")
	if err != nil || !bytes.Equal(got, asset) {
		t.Fatalf("exported asset=%v err=%v", got, err)
	}
}
