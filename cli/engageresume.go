package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runEngageResume(args []string) error {
	fs := newFlagSet("engage resume")
	var workspace, model, session, role, sessionCDP string
	fs.StringVar(&workspace, "workspace", "", "engagement workspace directory (default: the most recent engagement)")
	fs.StringVar(&model, "model", "", "chat model id (default: the resolved model)")
	fs.StringVar(&session, "session", "", "web role session file")
	fs.StringVar(&role, "role", "", "named web role")
	fs.StringVar(&sessionCDP, "session-cdp", "", "loopback signed-in Chrome CDP endpoint")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true, "model": true, "session": true, "role": true, "session-cdp": true})); err != nil {
		return err
	}
	if len(fs.Args()) == 1 && workspace == "" {
		workspace = fs.Args()[0]
	} else if len(fs.Args()) != 0 {
		return usageErr("engage resume accepts one workspace path, or --workspace and --model")
	}
	if strings.TrimSpace(workspace) == "" {
		var err error
		workspace, err = latestEngagementDir()
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(workspace, "run.json")); err != nil {
		return fmt.Errorf("engage resume: a RoE policy checkpoint is required: %w", err)
	}
	resume := []string{"--resume", workspace}
	if model != "" {
		resume = append(resume, "--model", model)
	}
	if sessionCDP != "" || session != "" || role != "" {
		resume = append(resume, "--session", session, "--role", role, "--session-cdp", sessionCDP)
	}
	return runEngage(resume)
}
