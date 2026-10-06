package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func migrateEngagePolicy(args []string) error {
	fs := newFlagSet("engage migrate")
	write := fs.Bool("write", false, "write ROE.md and archive the second config")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("engage migrate: use --write or no arguments for a preview")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	configPath := filepath.Join(cwd, ".blkchain", "config.yaml")
	info, err := os.Lstat(configPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return fmt.Errorf("engage: legacy configuration must be a regular file within 256 KiB")
	}
	cfg, err := loadEngageConfig(configPath)
	if err != nil {
		return err
	}
	roe, err := ParseRoE(strings.NewReader(roeTemplate))
	if err != nil {
		return err
	}
	roePath := filepath.Join(cwd, "ROE.md")
	existing := false
	if info, err := os.Lstat(roePath); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("engage: existing ROE.md must be a regular file")
		}
		existing = true
		file, err := os.Open(roePath)
		if err != nil {
			return err
		}
		roe, err = ParseRoE(file)
		file.Close()
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, binary := range cfg.DeniedBinaries {
		found := false
		for _, rule := range roe.Policy.Commands {
			found = found || strings.EqualFold(rule.Binary, binary) && rule.Arg == ""
		}
		if found {
			continue
		}
		if err := addRoEDenial(roe.Policy, "binary: "+binary); err != nil {
			return err
		}
	}
	roe.Policy.Allowed = nil
	if cfg.MaxActions > 0 && cfg.MaxActions < roe.Policy.MaxActions {
		roe.Policy.MaxActions = cfg.MaxActions
	}
	if cfg.WallSeconds > 0 && cfg.WallSeconds < roe.Policy.WallSeconds {
		roe.Policy.WallSeconds = cfg.WallSeconds
		if roe.Policy.CommandSeconds > cfg.WallSeconds {
			roe.Policy.CommandSeconds = cfg.WallSeconds
		}
	}
	text := renderRoEPolicy(roe)
	if _, err := ParseRoE(strings.NewReader(text)); err != nil {
		return fmt.Errorf("engage: generated policy is invalid: %w", err)
	}
	candidate := roePath
	if existing {
		candidate += ".migrated"
	}
	archive := configPath + ".migrated"
	if !*write {
		fmt.Fprint(os.Stdout, text)
		fmt.Fprintf(os.Stderr, "Preview: create %s. Allowed actions are empty until the operator grants them. Copy denied binaries and tighten resource caps.\n", candidate)
		if existing {
			fmt.Fprintf(os.Stderr, "Preserve %s and %s.\n", roePath, configPath)
		} else {
			fmt.Fprintf(os.Stderr, "Archive %s as %s.\n", configPath, archive)
		}
		return nil
	}
	file, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(text)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if existing {
		fmt.Fprintf(os.Stdout, "Created %s. Existing ROE.md and configuration remain unchanged.\n", candidate)
		return nil
	}
	if err := os.Link(configPath, archive); err != nil {
		return fmt.Errorf("created %s, but configuration archival failed: %w", candidate, err)
	}
	if err := os.Remove(configPath); err != nil {
		return fmt.Errorf("created %s and %s, but could not remove the old configuration: %w", candidate, archive, err)
	}
	fmt.Fprintf(os.Stdout, "Created %s with no allowed actions. Archived %s.\n", candidate, archive)
	return nil
}

func renderRoEPolicy(roe *RoE) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Rules of Engagement\n\n## Summary\n%s\n\n## Targets\n", roe.Summary)
	for _, target := range roe.Targets {
		fmt.Fprintf(&b, "- %s\n", target)
	}
	in, out := roe.Scope.Entries()
	if roe.Scope.Local() {
		in = append(in, "local")
	}
	for _, section := range []struct {
		name    string
		entries []string
	}{{"In Scope", in}, {"Out of Scope", out}, {"Allowed Actions", roe.Policy.Allowed}, {"Denied Actions", roe.Policy.Denied}} {
		fmt.Fprintf(&b, "\n## %s\n", section.name)
		for _, entry := range section.entries {
			fmt.Fprintf(&b, "- %s\n", entry)
		}
	}
	b.WriteString("\n## Denied Commands\n")
	for _, rule := range roe.Policy.Commands {
		if rule.Arg == "" {
			fmt.Fprintf(&b, "- binary: %s\n", rule.Binary)
		} else {
			fmt.Fprintf(&b, "- argument: %s %s\n", rule.Binary, rule.Arg)
		}
	}
	if rate, ok := roe.Scope.Rate(); ok {
		fmt.Fprintf(&b, "\n## Rate\n%d/%s\n", rate.N, map[string]string{"1s": "s", "1m0s": "m", "1h0m0s": "h"}[rate.Per.String()])
	}
	if roe.AutoActions != nil {
		b.WriteString("\n## Autonomous Actions\n")
		for _, rule := range roe.AutoActions.rules {
			fmt.Fprintf(&b, "- %s/%s %s\n", rule.phase, rule.surface, rule.target)
		}
	}
	p := roe.Policy
	fmt.Fprintf(&b, "\n## Resource Caps\nmax_commands: %d\nmax_actions: %d\nwall_seconds: %d\ncommand_seconds: %d\noutput_bytes: %d\ntotal_bytes: %d\nparallel: %d\n\n## Runner\nid: %s\n", p.MaxCommands, p.MaxActions, p.WallSeconds, p.CommandSeconds, p.OutputBytes, p.TotalBytes, p.Parallel, p.RunnerID)
	if p.RunnerImage != "" {
		fmt.Fprintf(&b, "image: %s\n", p.RunnerImage)
	}
	return b.String()
}

func stopEngageWorkspace(args []string) error {
	fs := newFlagSet("engage stop")
	workspace := fs.String("workspace", "", "engagement workspace")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *workspace == "" || len(fs.Args()) != 0 {
		return usageErr("engage stop: --workspace PATH is required")
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(*workspace, "run.json"), &metadata); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(*workspace, "STOP"), []byte("operator stop\n"))
}
