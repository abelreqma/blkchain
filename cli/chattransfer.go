package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/tooldef"
)

const (
	chatTransferMaxFiles   = 1000
	chatTransferMaxEntries = 5000
	chatTransferMaxBytes   = 10 << 20
)

type chatTransferArgs struct {
	Source      string `json:"source" desc:"path explicitly named in the current user request"`
	Destination string `json:"destination,omitempty" desc:"relative destination inside the other workspace"`
}

func chatTransferPath(root, path string) (string, error) {
	if path == "." || path == "./" {
		return ".", nil
	}
	r, clean, err := chatWorkspaceFile(root, path)
	if err != nil {
		return "", err
	}
	r.Close()
	return clean, nil
}

func chatCopyWorkspace(sourceRoot, destinationRoot, source, destination string) (int, error) {
	source, err := chatTransferPath(sourceRoot, source)
	if err != nil {
		return 0, err
	}
	if destination == "" {
		destination = filepath.Base(source)
		if source == "." {
			destination = "project"
		}
	}
	destination, err = chatTransferPath(destinationRoot, destination)
	if err != nil {
		return 0, err
	}
	r, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	info, err := r.Stat(source)
	if err != nil {
		return 0, err
	}
	if info.Mode().IsRegular() {
		data, err := chatReadRawFile(sourceRoot, source)
		if err != nil {
			return 0, err
		}
		if err := chatWriteFile(destinationRoot, destination, data, ""); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("source must be a regular file or directory")
	}
	if destination == "." {
		return 0, fmt.Errorf("directory destination must be a new path")
	}
	w, err := os.OpenRoot(destinationRoot)
	if err != nil {
		return 0, err
	}
	defer w.Close()
	if _, err := w.Stat(destination); err == nil {
		return 0, fmt.Errorf("destination already exists")
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	if err := w.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return 0, err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 0, err
	}
	tmp := filepath.Join(filepath.Dir(destination), fmt.Sprintf("blk-transfer-%x", random))
	if err := w.Mkdir(tmp, 0o700); err != nil {
		return 0, err
	}
	defer w.RemoveAll(tmp)
	count, total, visited := 0, 0, 0
	err = fs.WalkDir(r.FS(), source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > chatTransferMaxEntries {
			return fmt.Errorf("transfer exceeds %d entries", chatTransferMaxEntries)
		}
		if path == source {
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".") {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		if count >= chatTransferMaxFiles {
			return fmt.Errorf("transfer exceeds %d files", chatTransferMaxFiles)
		}
		data, err := chatReadRawFile(sourceRoot, path)
		if err != nil {
			return err
		}
		total += len(data)
		if total > chatTransferMaxBytes {
			return fmt.Errorf("transfer exceeds %d bytes", chatTransferMaxBytes)
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(tmp, rel)
		if err := chatWriteFile(destinationRoot, target, data, ""); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return 0, err
	}
	if err := w.Rename(tmp, destination); err != nil {
		return 0, err
	}
	return count, nil
}

func newChatTransferTool(name, sourceRoot, destinationRoot, question string) tooldef.Tool {
	description := "Copy an explicitly named local file or directory into the empty persistent sandbox. Existing files are not overwritten."
	if name == "file_export" {
		description = "Copy an explicitly named sandbox file or directory into the local working directory. Existing files are not overwritten."
	}
	return newStoreTool(name, description, chatTransferArgs{},
		func(_ context.Context, args string) (string, error) {
			var in chatTransferArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil || strings.TrimSpace(in.Source) == "" {
				return name + ": invalid arguments", nil
			}
			if !strings.Contains(question, in.Source) || (in.Source == "." && !strings.Contains(question, "./")) {
				return name + ": source path must be named in the current user request", nil
			}
			count, err := chatCopyWorkspace(sourceRoot, destinationRoot, in.Source, in.Destination)
			if err != nil {
				return name + ": " + err.Error(), nil
			}
			return fmt.Sprintf("%s: copied %d file(s)", name, count), nil
		})
}
