package main

import (
	"blkchain/cli/internal/engagement"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/webanalysis"
)

// webbundle.go writes an analysis bundle under the engagement's evidence directory, refusing any name that leaves it.

// webBundleDirName is the directory inside the web evidence directory that holds a bundle.
const webBundleDirName = "bundle"

const maxBundleASTBytes = 64 << 20

// writeWebBundle writes every file of b under dir and returns the bundle-relative paths it wrote.
func writeWebBundle(dir string, b webanalysis.Bundle) ([]string, error) {
	if dir == "" {
		return nil, errors.New("bundle directory required")
	}
	// An absolute directory is required, so a relative one never resolves against the working directory.
	if !filepath.IsAbs(dir) {
		return nil, errors.New("bundle directory must be absolute: " + webanalysis.SafeText(dir))
	}
	root := filepath.Clean(dir)
	parent := filepath.Dir(root)
	if err := webExportDir(parent); err != nil {
		return nil, err
	}
	st, err := os.Lstat(root)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	existing := err == nil
	if existing {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("invalid bundle directory")
		}
		if err := os.Chmod(root, 0700); err != nil {
			return nil, err
		}
	}
	staged, err := os.MkdirTemp(parent, ".bundle-new-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staged)
	written, err := writeWebBundleFiles(staged, b)
	if err != nil {
		return nil, err
	}
	if !existing {
		if err := os.Rename(staged, root); err != nil {
			return nil, err
		}
		return written, nil
	}
	old, err := os.MkdirTemp(parent, ".bundle-old-")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(old); err != nil {
		return nil, err
	}
	if err := os.Rename(root, old); err != nil {
		return nil, err
	}
	if err := os.Rename(staged, root); err != nil {
		if restoreErr := os.Rename(old, root); restoreErr != nil {
			return nil, errors.Join(err, restoreErr)
		}
		return nil, err
	}
	return written, os.RemoveAll(old)
}

func writeWebBundleFiles(root string, b webanalysis.Bundle) ([]string, error) {
	var written []string
	for _, f := range b.Files {
		path, err := bundleFilePath(root, f.Name)
		if err != nil {
			return written, err
		}
		if parent := filepath.Dir(path); parent != root {
			if err := webExportDir(parent); err != nil {
				return written, err
			}
		}
		if err := webExportFile(path, f.Data); err != nil {
			return written, err
		}
		written = append(written, f.Name)
	}
	return written, nil
}

// bundleFilePath resolves one bundle file name under root, refusing rather than cleaning anything that escapes it.
func bundleFilePath(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
		return "", errors.New("invalid bundle file name " + webanalysis.SafeText(name))
	}
	if name != filepath.ToSlash(filepath.Clean(name)) {
		return "", errors.New("invalid bundle file name " + webanalysis.SafeText(name))
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("bundle file name leaves the bundle directory")
	}
	return path, nil
}

// webBundleDir is the bundle directory inside an engagement's web evidence.
func webBundleDir(evidenceDir string) string {
	return filepath.Join(evidenceDir, "web", webBundleDirName)
}

// webBundleTrees reads the syntax trees a snapshot's artifacts hold, naming each one it could not load.
func webBundleTrees(ws *engagement.Workspace, s webanalysis.Snapshot) ([]webanalysis.AST, []string) {
	var trees []webanalysis.AST
	var gaps []string
	remaining := maxBundleASTBytes
	for _, a := range s.Artifacts {
		if a.Kind != webanalysis.ASTArtifactKind {
			continue
		}
		if remaining <= 0 {
			gaps = append(gaps, "syntax tree "+a.Hash+": bundle tree budget exhausted")
			continue
		}
		body, err := ws.Store.WebBlob(a.Hash)
		if err != nil {
			gaps = append(gaps, "syntax tree "+a.Hash+": "+err.Error())
			continue
		}
		tree, err := webanalysis.UnmarshalAST(body)
		if err != nil {
			gaps = append(gaps, "syntax tree "+a.Hash+": "+err.Error())
			continue
		}
		if tree.RawBytes > remaining {
			gaps = append(gaps, "syntax tree "+a.Hash+": bundle tree budget exhausted")
			continue
		}
		remaining -= tree.RawBytes
		trees = append(trees, tree)
	}
	return trees, gaps
}
