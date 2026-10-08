package main

import (
	"archive/tar"
	"blkchain/cli/internal/webanalysis"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const webPackageIntegrity = "wPYSwEBJY9GHraISXqyqtx0na0LpO3XEX7jNDhntbex7tzUS7kLnZsOlFruFJB4Hi/rhDMjXGqHewDZ68nYZVw=="

func webVerifyPackage(dir string) error {
	fail := errors.New("playwright package must match the pinned 1.62.1 tarball and integrity hash")
	file, err := os.Open(filepath.Join(dir, "playwright-core-1.62.1.tgz"))
	if err != nil {
		return fail
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<20 {
		return fail
	}
	h := sha512.New()
	if _, err = io.Copy(h, io.LimitReader(file, 32<<20+1)); err != nil || base64.StdEncoding.EncodeToString(h.Sum(nil)) != webPackageIntegrity {
		return fail
	}
	if _, err = file.Seek(0, 0); err != nil {
		return fail
	}
	z, err := gzip.NewReader(file)
	if err != nil {
		return fail
	}
	defer z.Close()
	reader := tar.NewReader(io.LimitReader(z, 128<<20))
	count, total := 0, int64(0)
	expected := map[string]bool{}
	for {
		entry, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return fail
		}
		count++
		total += entry.Size
		clean := filepath.Clean(entry.Name)
		if count > 10000 || total > 128<<20 || entry.Size < 0 || !strings.HasPrefix(clean, "package/") {
			return fail
		}
		if entry.Typeflag == tar.TypeDir {
			continue
		}
		if entry.Typeflag != tar.TypeReg {
			return fail
		}
		b, e := io.ReadAll(io.LimitReader(reader, entry.Size+1))
		if e != nil || int64(len(b)) != entry.Size {
			return fail
		}
		expected[clean] = true
		path := filepath.Join(dir, clean)
		fi, e := os.Lstat(path)
		if e != nil || !fi.Mode().IsRegular() || fi.Size() != entry.Size {
			return fail
		}
		actual, e := os.ReadFile(path)
		if e != nil || webanalysis.Hash(actual) != webanalysis.Hash(b) {
			return fail
		}
	}
	if count < 2 {
		return fail
	}
	seen := 0
	return filepath.WalkDir(filepath.Join(dir, "package"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fail
		}
		seen++
		if seen > 10000 || entry.Type()&os.ModeSymlink != 0 {
			return fail
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil || !expected[relative] {
			return fail
		}
		return nil
	})
}
