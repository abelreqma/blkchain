package webcollect

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestWaybackPublicServiceE2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_WAYBACK_E2E") != "1" {
		t.Skip("requires explicit public Wayback validation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	archive := NewArchive(func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && (u.Hostname() == "example.com" || u.Hostname() == "www.example.com")
	})
	rows, next, err := archive.Query(ctx, "https://example.com/", "host", "", "")
	if err != nil {
		t.Fatalf("public CDX unavailable; live pagination and capture validation remain incomplete: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("public CDX returned no fixture captures")
	}
	t.Logf("public index captures=%d resume=%t", len(rows), next != "")
	if next == "" {
		t.Fatal("public fixture did not exercise resume pagination")
	}
	second, again, err := archive.Query(ctx, "https://example.com/", "host", "", next)
	if err != nil || len(second) == 0 || again == next {
		t.Fatalf("resume pagination failed: captures=%d repeated=%t err=%v", len(second), again == next, err)
	}
	t.Logf("public second page captures=%d resume advanced=%t", len(second), again != next)
	out, err := archive.Fetch(ctx, rows[0])
	if err != nil {
		t.Fatalf("indexed capture unavailable: status=%d error=%v", out.Status, err)
	}
	if !out.Complete || len(out.Body) == 0 {
		t.Fatal("indexed public capture body incomplete")
	}
	t.Logf("public capture status=%d bytes=%d", out.Status, len(out.Body))
	missing, _, err := archive.Query(ctx, "https://example.com/.blkchain-validation-missing-20261004", "exact", "", "")
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing-capture index check: count=%d error=%v", len(missing), err)
	}
	out, err = archive.Fetch(ctx, Capture{Timestamp: "20261004000000", Original: "https://example.com/.blkchain-validation-missing-20261004"})
	if err == nil || out.Status != 404 {
		t.Fatalf("missing capture check incomplete: status=%d err=%v", out.Status, err)
	}
	t.Logf("missing capture remained a gap: %v", err)
	t.Log("Throttling is validated against controlled 429/503 fixtures; a live throttle response is not required or induced.")
}
