package main

import (
	"fmt"
	"strings"
)

func runEngageResume(args []string) error {
	fs := newFlagSet("engage resume")
	var workspace, model string
	fs.StringVar(&workspace, "workspace", "", "engagement workspace directory (default: the most recent engagement)")
	fs.StringVar(&model, "model", "", "chat model id (default: the resolved model)")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true, "model": true})); err != nil {
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
	checkpoint, err := loadEngageCheckpoint(workspace)
	if err != nil {
		return fmt.Errorf("engage resume: %w", err)
	}
	o := engageOpts{workspace: workspace, model: model, auto: checkpoint.Auto, autoOverride: checkpoint.AutoOverride}
	return runEngageWithOptions(o, checkpoint.Goal, &checkpoint)
}
