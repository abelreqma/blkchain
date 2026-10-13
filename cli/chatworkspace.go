package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/histstore"
)

const (
	chatToolHostSandbox = "sandbox"
	chatToolHostLocal   = "local"
)

func chatWorkspaceRoot(host string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", err
	}
	switch host {
	case chatToolHostLocal:
		return cwd, nil
	case "", chatToolHostSandbox:
		path, err := histstore.DBPath()
		if err != nil {
			return "", err
		}
		base := filepath.Join(filepath.Dir(path), "workspaces")
		if err := privateDir(base); err != nil {
			return "", err
		}
		digest := sha256.Sum256([]byte(cwd))
		root := filepath.Join(base, hex.EncodeToString(digest[:16]))
		if err := privateDir(root); err != nil {
			return "", err
		}
		return root, nil
	default:
		return "", fmt.Errorf("tool host: choose %s or %s", chatToolHostSandbox, chatToolHostLocal)
	}
}

func chatWorkspaceFile(root, name string) (*os.Root, string, error) {
	name = filepath.Clean(strings.TrimSpace(name))
	if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return nil, "", errors.New("path must stay inside the selected workspace")
	}
	for _, part := range strings.Split(name, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") {
			return nil, "", errors.New("hidden paths are unavailable")
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, "", err
	}
	prefix := ""
	for _, part := range strings.Split(name, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, part)
		info, err := r.Lstat(prefix)
		if os.IsNotExist(err) {
			break
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			r.Close()
			return nil, "", errors.New("workspace path cannot contain a symbolic link")
		}
	}
	return r, name, nil
}
