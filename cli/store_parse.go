package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"blkchain/cli/internal/engagement"
)

func parsedFindingID(task string, evidenceID int64, title, asset, detail string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s", task, evidenceID, title, asset, detail)))
	return "parsed:" + hex.EncodeToString(sum[:12])
}

func syncParsedFindings(ctx context.Context, st *engagement.Store) error {
	cursor, err := st.FindingParseCursor(ctx)
	if err != nil {
		return err
	}
	for {
		rows, err := st.EvidenceAfter(ctx, cursor, 500)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			validSurface := false
			for _, surface := range engagement.AllSurfaces() {
				if row.Surface == surface {
					validSurface = true
					break
				}
			}
			if !validSurface {
				continue
			}
			task, err := st.GetTask(row.TaskID)
			if err != nil {
				return err
			}
			prov := Provenance{TaskID: row.TaskID, EvidenceID: row.ID}
			candidates := []engagement.Finding{}
			for _, parsed := range parseFindings(prov, row.Quote) {
				asset := parsed.Host
				if asset == "" {
					asset = task.Target
				}
				detail := parsed.Detail
				if parsed.Port > 0 {
					detail = fmt.Sprintf("port=%d %s", parsed.Port, detail)
				}
				asset, detail = capRunes(asset, 256), capRunes(detail, 2048)
				if asset == "" {
					asset = "unknown asset"
				}
				candidates = append(candidates, engagement.Finding{
					ID: parsedFindingID(row.TaskID, row.ID, parsed.Title, asset, detail), Surface: row.Surface,
					TaskID: row.TaskID, Asset: asset, Title: parsed.Title, Status: engagement.FindingLead,
					Severity: string(parsed.Severity), Confidence: "code-parsed", Detail: detail,
					EvidenceIDs: []int64{row.ID}, Source: "code-parsed",
				})
			}
			for _, parsed := range parseTLSInfo(prov, row.Quote) {
				asset := parsed.Host
				if asset == "" {
					asset = task.Target
				}
				asset = capRunes(asset, 256)
				if asset == "" {
					asset = "unknown asset"
				}
				detail := capRunes(fmt.Sprintf("port=%d protocol=%s issue=%s", parsed.Port, parsed.Protocol, parsed.Issue), 2048)
				title := "tls-" + parsed.Issue
				candidates = append(candidates, engagement.Finding{
					ID: parsedFindingID(row.TaskID, row.ID, title, asset, detail), Surface: row.Surface,
					TaskID: row.TaskID, Asset: asset, Title: title, Status: engagement.FindingLead,
					Severity: "info", Confidence: "code-parsed", Detail: detail,
					EvidenceIDs: []int64{row.ID}, Source: "code-parsed",
				})
			}
			for _, finding := range candidates {
				exists, err := st.HasFinding(ctx, finding.ID)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
				if _, err := st.SaveFinding(ctx, finding); err != nil {
					if exists, checkErr := st.HasFinding(ctx, finding.ID); checkErr == nil && exists {
						continue
					}
					return err
				}
			}
		}
		cursor = rows[len(rows)-1].ID
		if err := st.AdvanceFindingParseCursor(ctx, cursor); err != nil {
			return err
		}
	}
}
