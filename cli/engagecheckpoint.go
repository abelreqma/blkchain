package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"blkchain/cli/internal/secgate"
)

const (
	maxEngageCheckpointBytes = 64 << 10
	maxEngageScopeBytes      = 1 << 20
)

type engageCheckpoint struct {
	Goal         string `json:"goal"`
	ProjectDir   string `json:"project_dir"`
	ScopeKind    string `json:"scope_kind"`
	ScopeSHA256  string `json:"scope_sha256,omitempty"`
	Auto         bool   `json:"auto"`
	AutoOverride bool   `json:"auto_override"`
}

func (c engageCheckpoint) valid() error {
	if strings.TrimSpace(c.Goal) == "" || len(c.Goal) > 16000 || !filepath.IsAbs(c.ProjectDir) {
		return errors.New("engagement checkpoint has an invalid goal or project directory")
	}
	switch c.ScopeKind {
	case "roe", "scope", "none":
	default:
		return errors.New("engagement checkpoint has an invalid scope kind")
	}
	if c.Auto && c.ScopeKind == "none" && !c.AutoOverride {
		return errors.New("automatic engagement checkpoint has no scope")
	}
	if c.ScopeKind == "none" {
		if c.ScopeSHA256 != "" {
			return errors.New("engagement checkpoint has an unexpected scope digest")
		}
	} else if len(c.ScopeSHA256) != 64 {
		return errors.New("engagement checkpoint has no valid scope digest")
	} else if _, err := hex.DecodeString(c.ScopeSHA256); err != nil {
		return errors.New("engagement checkpoint has no valid scope digest")
	}
	return nil
}

func saveEngageCheckpoint(wsDir string, c engageCheckpoint, scopeSource string) error {
	if c.ScopeKind != "none" {
		f, err := os.Open(scopeSource)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxEngageScopeBytes+1))
		f.Close()
		if readErr != nil {
			return readErr
		}
		if len(data) > maxEngageScopeBytes {
			return errors.New("engagement scope exceeds the size limit")
		}
		digest := sha256.Sum256(data)
		c.ScopeSHA256 = hex.EncodeToString(digest[:])
		name := "ROE.md"
		if c.ScopeKind == "roe" {
			if _, err := ParseRoE(bytes.NewReader(data)); err != nil {
				return err
			}
		} else {
			name = "scope.txt"
			if _, err := secgate.ParseScope(bytes.NewReader(data)); err != nil {
				return err
			}
		}
		dest := filepath.Join(wsDir, name)
		if filepath.Clean(scopeSource) != filepath.Clean(dest) {
			out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			if _, err := out.Write(data); err != nil {
				out.Close()
				os.Remove(dest)
				return err
			}
			if err := out.Sync(); err != nil {
				out.Close()
				os.Remove(dest)
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		} else if info, err := os.Lstat(dest); err != nil || !info.Mode().IsRegular() {
			return errors.New("engagement scope in workspace must be a regular file")
		}
	}
	if err := c.valid(); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	path := filepath.Join(wsDir, "checkpoint.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func loadEngageCheckpoint(wsDir string) (engageCheckpoint, error) {
	path := filepath.Join(wsDir, "checkpoint.json")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return engageCheckpoint{}, fmt.Errorf("engagement checkpoint: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return engageCheckpoint{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxEngageCheckpointBytes {
		return engageCheckpoint{}, errors.New("engagement checkpoint is not a bounded regular file")
	}
	var c engageCheckpoint
	dec := json.NewDecoder(io.LimitReader(f, maxEngageCheckpointBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return engageCheckpoint{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return engageCheckpoint{}, errors.New("engagement checkpoint has trailing data")
	}
	if err := c.valid(); err != nil {
		return engageCheckpoint{}, err
	}
	if c.ScopeKind != "none" {
		if _, err := checkpointScopeBytes(wsDir, c); err != nil {
			return engageCheckpoint{}, err
		}
	}
	return c, nil
}

func checkpointScopeBytes(wsDir string, c engageCheckpoint) ([]byte, error) {
	name := "ROE.md"
	if c.ScopeKind == "scope" {
		name = "scope.txt"
	}
	path := filepath.Join(wsDir, name)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("engagement scope: %w", err)
	}
	scope := os.NewFile(uintptr(fd), path)
	info, statErr := scope.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > maxEngageScopeBytes {
		scope.Close()
		return nil, errors.New("engagement scope is not a bounded regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(scope, maxEngageScopeBytes+1))
	scope.Close()
	if readErr != nil || len(data) > maxEngageScopeBytes {
		return nil, errors.New("engagement scope cannot be read within the size limit")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != c.ScopeSHA256 {
		return nil, errors.New("engagement scope differs from the saved authorization")
	}
	return data, nil
}

func checkpointScope(wsDir string, c engageCheckpoint) (*secgate.Scope, string, string, error) {
	if c.ScopeKind == "none" {
		return nil, "(none)", "", nil
	}
	data, err := checkpointScopeBytes(wsDir, c)
	if err != nil {
		return nil, "", "", err
	}
	if c.ScopeKind == "scope" {
		scope, err := secgate.ParseScope(bytes.NewReader(data))
		return scope, filepath.Join(wsDir, "scope.txt"), "", err
	}
	roe, err := ParseRoE(bytes.NewReader(data))
	if err != nil {
		return nil, "", "", err
	}
	path := filepath.Join(wsDir, "ROE.md")
	return roe.Scope, path, path, nil
}
