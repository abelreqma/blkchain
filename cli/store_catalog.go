package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
)

type storedEngagement struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Workspace string         `json:"workspace"`
	Revision  string         `json:"revision"`
	UpdatedAt string         `json:"updated_at"`
	Surfaces  map[string]int `json:"surfaces"`
	Findings  map[string]int `json:"findings"`
	Targets   []string       `json:"targets"`
	Error     string         `json:"error,omitempty"`
}

func storeRoot() (string, error) {
	cfg, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "engagements"), nil
}

func existingEngagementDB(dir string) (string, error) {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return "", errors.New("engagement workspace is not a directory")
	}
	path := filepath.Join(dir, "engagement.db")
	st, err = os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return "", errors.New("engagement database is missing or not a regular file")
	}
	return path, nil
}

func readStoredEngagement(ctx context.Context, dir, id string) (storedEngagement, error) {
	path, err := existingEngagementDB(dir)
	if err != nil {
		return storedEngagement{}, err
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_busy_timeout=5000"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return storedEngagement{}, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return storedEngagement{}, err
	}
	item := storedEngagement{ID: id, Workspace: dir, Surfaces: map[string]int{}, Findings: map[string]int{}, Targets: []string{}}
	if err := db.QueryRowContext(ctx, `SELECT coalesce((SELECT v FROM meta WHERE k='name'),'')`).Scan(&item.Name); err != nil {
		return storedEngagement{}, err
	}
	if err := db.QueryRowContext(ctx, `SELECT coalesce((SELECT v FROM meta WHERE k='revision'),'0')`).Scan(&item.Revision); err != nil {
		return storedEngagement{}, err
	}
	var hasSurface int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('task') WHERE name='surface'`).Scan(&hasSurface); err != nil {
		return storedEngagement{}, err
	}
	surfaceQuery := `SELECT 'unclassified', count(*) FROM task`
	if hasSurface != 0 {
		surfaceQuery = `SELECT coalesce(nullif(surface,''),'unclassified'), count(*) FROM task GROUP BY coalesce(nullif(surface,''),'unclassified') ORDER BY 1`
	}
	rows, err := db.QueryContext(ctx, surfaceQuery)
	if err != nil {
		return storedEngagement{}, err
	}
	for rows.Next() {
		var surface string
		var count int
		if err := rows.Scan(&surface, &count); err != nil {
			rows.Close()
			return storedEngagement{}, err
		}
		item.Surfaces[surface] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storedEngagement{}, err
	}
	rows, err = db.QueryContext(ctx, `SELECT DISTINCT target FROM task WHERE target<>'' ORDER BY target LIMIT 5`)
	if err != nil {
		return storedEngagement{}, err
	}
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			rows.Close()
			return storedEngagement{}, err
		}
		item.Targets = append(item.Targets, webanalysis.RedactText(webanalysis.RedactURL(target)))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return storedEngagement{}, err
	}
	findingTable := false
	webTable := false
	for _, source := range []struct{ table, query string }{
		{"finding_record", `SELECT surface,count(*) FROM finding_record GROUP BY surface`},
		{"web_record", `SELECT 'web',count(*) FROM web_record WHERE kind='finding'`},
	} {
		var exists int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, source.table).Scan(&exists); err != nil {
			return storedEngagement{}, err
		}
		if exists == 0 {
			continue
		}
		if source.table == "finding_record" {
			findingTable = true
		} else {
			webTable = true
		}
		rows, err := db.QueryContext(ctx, source.query)
		if err != nil {
			return storedEngagement{}, err
		}
		for rows.Next() {
			var surface string
			var count int
			if err := rows.Scan(&surface, &count); err != nil {
				rows.Close()
				return storedEngagement{}, err
			}
			item.Findings[surface] += count
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return storedEngagement{}, err
		}
	}
	if findingTable && webTable {
		var reviewedWeb int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_record f JOIN web_record w ON f.id='web:'||w.id WHERE w.kind='finding'`).Scan(&reviewedWeb); err != nil {
			return storedEngagement{}, err
		}
		item.Findings["web"] -= reviewedWeb
	}
	st, err := os.Stat(path)
	if err == nil {
		item.UpdatedAt = st.ModTime().UTC().Format(time.RFC3339)
	}
	return item, nil
}

func listStoredEngagements(ctx context.Context) ([]storedEngagement, error) {
	root, err := storeRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []storedEngagement{}, nil
	}
	if err != nil {
		return nil, err
	}
	items := []storedEngagement{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if len(items) >= 10000 {
			return nil, errors.New("engagement catalog limit exceeded")
		}
		dir := filepath.Join(root, entry.Name())
		if _, err := existingEngagementDB(dir); err != nil {
			continue
		}
		item, err := readStoredEngagement(ctx, dir, entry.Name())
		if err != nil {
			item = storedEngagement{ID: entry.Name(), Workspace: dir, Error: err.Error()}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return items, nil
}

func selectStoredWorkspace(ctx context.Context, id, dir string) (*engagement.Workspace, string, error) {
	if id != "" && dir != "" {
		return nil, "", errors.New("choose --id or --workspace")
	}
	if dir == "" {
		items, err := listStoredEngagements(ctx)
		if err != nil {
			return nil, "", err
		}
		if len(items) == 0 {
			return nil, "", errors.New("no engagement workspaces found")
		}
		if id == "" {
			for _, item := range items {
				if item.Error == "" {
					id = item.ID
					break
				}
			}
			if id == "" {
				return nil, "", errors.New("no readable engagement workspaces found; run blk store list")
			}
		}
		for _, item := range items {
			if item.ID == id {
				if item.Error != "" {
					return nil, "", fmt.Errorf("engagement %s cannot be opened: %s", id, item.Error)
				}
				dir = item.Workspace
				break
			}
		}
		if dir == "" {
			return nil, "", fmt.Errorf("engagement %q not found; run blk store list", id)
		}
	} else {
		var err error
		dir, err = filepath.Abs(dir)
		if err != nil {
			return nil, "", err
		}
		id = filepath.Base(dir)
	}
	if strings.TrimSpace(id) == "" {
		return nil, "", errors.New("engagement id is empty")
	}
	if _, err := existingEngagementDB(dir); err != nil {
		return nil, "", err
	}
	ws, err := engagement.OpenWorkspace(dir)
	if err == nil {
		err = ws.Store.ImportActionTranscript(ctx, filepath.Join(dir, "actions.jsonl"))
		if err == nil {
			err = syncParsedFindings(ctx, ws.Store)
		}
		if err != nil {
			ws.Close()
		}
	}
	return ws, id, err
}
