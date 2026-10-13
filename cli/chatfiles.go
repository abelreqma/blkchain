package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

const (
	chatFileMaxBytes     = 10 << 20
	chatFileOutputBytes  = 64 << 10
	chatSearchMaxFiles   = 1000
	chatSearchMaxEntries = 5000
	chatSearchMaxHits    = 100
	chatSearchMaxBytes   = 10 << 20
)

type chatFileReadArgs struct {
	Path   string `json:"path" desc:"file path inside the selected workspace"`
	Offset int    `json:"offset,omitempty" desc:"first line to return, starting at 1"`
	Limit  int    `json:"limit,omitempty" desc:"maximum lines to return, at most 400"`
}

func chatReadFile(root, name string) ([]byte, error) {
	data, _, _, err := chatReadTextFile(root, name)
	return data, err
}

func chatReadTextFile(root, name string) ([]byte, []byte, string, error) {
	data, err := chatReadRawFile(root, name)
	if err != nil {
		return nil, nil, "", err
	}
	if kind := chatDocumentType(name); kind != "" {
		text, err := chatDocumentText(name, data)
		if err != nil {
			return nil, nil, "", err
		}
		return text, data, kind, nil
	}
	if utf8.Valid(data) && bytes.IndexByte(data, 0) < 0 {
		return data, data, "utf-8", nil
	}
	order, skip, encoding := binary.ByteOrder(nil), 0, ""
	switch {
	case len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe:
		order, skip, encoding = binary.LittleEndian, 2, "utf-16le"
	case len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff:
		order, skip, encoding = binary.BigEndian, 2, "utf-16be"
	default:
		even, odd, pairs := 0, 0, min(len(data)/2, 128)
		for i := 0; i < pairs; i++ {
			if data[i*2] == 0 {
				even++
			}
			if data[i*2+1] == 0 {
				odd++
			}
		}
		if pairs >= 4 && odd > pairs/2 && even <= pairs/10 {
			order, encoding = binary.LittleEndian, "utf-16le"
		} else if pairs >= 4 && even > pairs/2 && odd <= pairs/10 {
			order, encoding = binary.BigEndian, "utf-16be"
		}
	}
	if order == nil || (len(data)-skip)%2 != 0 {
		return nil, nil, "", fmt.Errorf("file is binary")
	}
	words := make([]uint16, (len(data)-skip)/2)
	for i := range words {
		words[i] = order.Uint16(data[skip+i*2:])
	}
	decoded := []byte(string(utf16.Decode(words)))
	if len(decoded) > chatFileMaxBytes || bytes.IndexByte(decoded, 0) >= 0 {
		return nil, nil, "", fmt.Errorf("decoded text exceeds the limit or is binary")
	}
	return decoded, data, encoding, nil
}

func chatReadRawFile(root, name string) ([]byte, error) {
	r, name, err := chatWorkspaceFile(root, name)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	info, err := r.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > chatFileMaxBytes {
		return nil, fmt.Errorf("file must be regular and at most %d bytes", chatFileMaxBytes)
	}
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, chatFileMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > chatFileMaxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", chatFileMaxBytes)
	}
	return data, nil
}

func newChatFileReadTool(root string) tooldef.Tool {
	return newStoreTool("file_read", "Read a text file inside the selected workspace with line numbers and a SHA-256 digest.", chatFileReadArgs{},
		func(_ context.Context, args string) (string, error) {
			var in chatFileReadArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "file_read: invalid arguments", nil
			}
			data, raw, encoding, err := chatReadTextFile(root, in.Path)
			if err != nil {
				return "file_read: " + err.Error(), nil
			}
			if in.Offset < 1 {
				in.Offset = 1
			}
			if in.Limit < 1 || in.Limit > 400 {
				in.Limit = 200
			}
			lines := strings.Split(string(data), "\n")
			start := min(in.Offset-1, len(lines))
			end := min(start+in.Limit, len(lines))
			digest := sha256.Sum256(raw)
			var out strings.Builder
			fmt.Fprintf(&out, "sha256=%x lines=%d encoding=%s\n", digest, len(lines), encoding)
			for i := start; i < end; i++ {
				line := fmt.Sprintf("%d|%s\n", i+1, lines[i])
				if out.Len()+len(line)+64 > chatFileOutputBytes {
					if i == start {
						return "file_read: line exceeds the output limit", nil
					}
					break
				}
				out.WriteString(line)
				start = i + 1
			}
			if start < len(lines) {
				fmt.Fprintf(&out, "next_offset=%d\n", start+1)
			}
			return secgate.WrapUntrusted("file", out.String()), nil
		})
}

type chatFileSearchArgs struct {
	Path    string `json:"path,omitempty" desc:"directory inside the selected workspace, default root"`
	Pattern string `json:"pattern" desc:"RE2 regular expression for file names or text"`
	Mode    string `json:"mode,omitempty" desc:"name or content, default content"`
}

func newChatFileSearchTool(root string) tooldef.Tool {
	return newStoreTool("file_search", "Search file names or bounded text content inside the selected workspace.", chatFileSearchArgs{},
		func(_ context.Context, args string) (string, error) {
			var in chatFileSearchArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil || len(in.Pattern) == 0 || len(in.Pattern) > 256 {
				return "file_search: invalid pattern", nil
			}
			if in.Mode == "" {
				in.Mode = "content"
			}
			if in.Mode != "name" && in.Mode != "content" {
				return "file_search: mode must be name or content", nil
			}
			pattern, err := regexp.Compile(in.Pattern)
			if err != nil {
				return "file_search: " + err.Error(), nil
			}
			base := in.Path
			if base == "" {
				base = "."
			}
			if base != "." {
				checked, clean, err := chatWorkspaceFile(root, base)
				if err != nil {
					return "file_search: " + err.Error(), nil
				}
				checked.Close()
				base = clean
			}
			r, err := os.OpenRoot(root)
			if err != nil {
				return "file_search: " + err.Error(), nil
			}
			defer r.Close()
			var out strings.Builder
			files, hits, scanned, visited := 0, 0, 0, 0
			err = fs.WalkDir(r.FS(), base, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				visited++
				if visited > chatSearchMaxEntries {
					return fs.SkipAll
				}
				if entry.IsDir() {
					if path != base && strings.HasPrefix(entry.Name(), ".") {
						return fs.SkipDir
					}
					return nil
				}
				if files >= chatSearchMaxFiles || hits >= chatSearchMaxHits || scanned >= chatSearchMaxBytes || out.Len() >= chatFileOutputBytes {
					return fs.SkipAll
				}
				if strings.HasPrefix(entry.Name(), ".") {
					return nil
				}
				if !entry.Type().IsRegular() {
					return nil
				}
				files++
				if in.Mode == "name" {
					if pattern.MatchString(path) {
						if out.Len()+len(path)+1 > chatFileOutputBytes {
							return fs.SkipAll
						}
						fmt.Fprintln(&out, path)
						hits++
					}
					return nil
				}
				info, err := entry.Info()
				if err != nil || info.Size() > int64(chatSearchMaxBytes-scanned) {
					return nil
				}
				data, err := chatReadFile(root, path)
				if err != nil {
					return nil
				}
				scanned += len(data)
				for line, text := range strings.Split(string(data), "\n") {
					if pattern.MatchString(text) {
						if out.Len()+len(path)+len(text)+32 > chatFileOutputBytes {
							return fs.SkipAll
						}
						fmt.Fprintf(&out, "%s:%d:%s\n", path, line+1, text)
						hits++
						if hits >= chatSearchMaxHits {
							return fs.SkipAll
						}
					}
				}
				return nil
			})
			if err != nil {
				return "file_search: " + err.Error(), nil
			}
			if hits == 0 {
				return "file_search: no matches", nil
			}
			return secgate.WrapUntrusted("file", out.String()), nil
		})
}

type chatFileWriteArgs struct {
	Path           string `json:"path" desc:"file path inside the selected workspace"`
	Content        string `json:"content" desc:"complete UTF-8 file content"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty" desc:"required when replacing an existing file"`
}

func chatWriteFile(root, path string, data []byte, expected string) error {
	if len(data) > chatFileMaxBytes {
		return fmt.Errorf("content must be at most %d bytes", chatFileMaxBytes)
	}
	r, path, err := chatWorkspaceFile(root, path)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := r.Stat(path); err == nil {
		if !info.Mode().IsRegular() || expected == "" {
			return fmt.Errorf("existing file requires expected_sha256")
		}
		old, err := chatReadRawFile(root, path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(old)
		if !strings.EqualFold(expected, hex.EncodeToString(digest[:])) {
			return fmt.Errorf("file changed since it was read")
		}
	} else if !errorsIsNotExist(err) {
		return err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".blk-write-%x", random))
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return r.Rename(tmp, path)
}

func errorsIsNotExist(err error) bool { return err != nil && os.IsNotExist(err) }

func newChatFileWriteTool(root string) tooldef.Tool {
	return newStoreTool("file_write", "Create a UTF-8 file or replace one after supplying the SHA-256 digest from file_read.", chatFileWriteArgs{},
		func(_ context.Context, args string) (string, error) {
			var in chatFileWriteArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "file_write: invalid arguments", nil
			}
			if chatDocumentType(in.Path) != "" {
				return "file_write: document formats are read-only in this tool", nil
			}
			if len(in.Content) > 1<<20 || !utf8.ValidString(in.Content) || strings.IndexByte(in.Content, 0) >= 0 {
				return "file_write: content must be UTF-8 text of at most 1048576 bytes", nil
			}
			if err := chatWriteFile(root, in.Path, []byte(in.Content), in.ExpectedSHA256); err != nil {
				return "file_write: " + err.Error(), nil
			}
			return "file_write: saved " + in.Path, nil
		})
}

type chatFilePatchArgs struct {
	Path string `json:"path" desc:"file path inside the selected workspace"`
	Old  string `json:"old" desc:"exact text to replace once"`
	New  string `json:"new" desc:"replacement text"`
}

func newChatFilePatchTool(root string) tooldef.Tool {
	return newStoreTool("file_patch", "Replace one exact text span in a workspace file and report the changed line.", chatFilePatchArgs{},
		func(_ context.Context, args string) (string, error) {
			var in chatFilePatchArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil || in.Old == "" {
				return "file_patch: invalid arguments", nil
			}
			if chatDocumentType(in.Path) != "" {
				return "file_patch: document formats are read-only in this tool", nil
			}
			old, raw, _, err := chatReadTextFile(root, in.Path)
			if err != nil {
				return "file_patch: " + err.Error(), nil
			}
			if bytes.Count(old, []byte(in.Old)) != 1 {
				return "file_patch: old text must match exactly once", nil
			}
			line := bytes.Count(old[:bytes.Index(old, []byte(in.Old))], []byte("\n")) + 1
			next := bytes.Replace(old, []byte(in.Old), []byte(in.New), 1)
			digest := sha256.Sum256(raw)
			if err := chatWriteFile(root, in.Path, next, hex.EncodeToString(digest[:])); err != nil {
				return "file_patch: " + err.Error(), nil
			}
			return fmt.Sprintf("file_patch: updated %s at line %d", in.Path, line), nil
		})
}
