package main

import (
	"os"
	"path/filepath"
	"strings"
)

func chatQuestionNamesFile(question string) bool {
	for _, field := range strings.Fields(question) {
		path := strings.Trim(field, `[](){}<>"'.,;!?`)
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return true
		}
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
		if chatFileExtensions[ext] {
			return true
		}
	}
	return false
}
