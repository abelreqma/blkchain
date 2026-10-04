package webcollect

import (
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Capture struct {
	Timestamp string `json:"timestamp"`
	Original  string `json:"original"`
	Status    int    `json:"status"`
	MIME      string `json:"mime"`
	Digest    string `json:"digest"`
}
type Archive struct {
	Resume  string
	Broker  *webacquire.Broker
	Base    string
	Allowed func(string) bool
	Public  func(context.Context, string) bool
}

func NewArchive(allowed func(string) bool) *Archive {
	a := &Archive{Base: "https://web.archive.org", Allowed: allowed}
	a.Public = func(ctx context.Context, host string) bool {
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil || len(ips) == 0 {
			return false
		}
		for _, v := range ips {
			if !v.IP.IsGlobalUnicast() || v.IP.IsPrivate() || v.IP.IsLoopback() || v.IP.IsLinkLocalUnicast() {
				return false
			}
		}
		return true
	}
	a.Broker = &webacquire.Broker{Policy: webacquire.Policy{Authorize: func(ctx context.Context, r webacquire.Request) error {
		u, e := webacquire.URL(r.URL)
		if e != nil || u.Scheme != "https" || u.Host != "web.archive.org" || r.Method != "GET" || len(r.Body) > 0 || len(r.Headers) > 0 {
			return errors.New("archive infrastructure request denied")
		}
		return nil
	}, IPAllowed: func(ip net.IP) bool {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}}}
	return a
}

var archiveTime = regexp.MustCompile(`^[0-9]{14}$`)

func (a *Archive) original(raw string) error {
	u, e := webacquire.URL(raw)
	if e != nil {
		return e
	}
	if a.Allowed == nil || !a.Allowed(raw) {
		return errors.New("archive original outside discovery scope")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return errors.New("private original is not sent to archive providers")
	}
	if strings.Contains(u.Hostname(), ".") == false {
		return errors.New("private host is not sent to archive providers")
	}
	for k := range u.Query() {
		if webanalysis.Sensitive(k) {
			return errors.New("sensitive original query is not sent to archive providers")
		}
	}
	return nil
}
func (a *Archive) Query(ctx context.Context, original, match, stamp, resume string) ([]Capture, string, error) {
	if e := a.original(original); e != nil {
		return nil, "", e
	}
	u, _ := webacquire.URL(original)
	if a.Public != nil && !a.Public(ctx, u.Hostname()) {
		return nil, "", errors.New("private original is not sent to archive providers")
	}
	if len(resume) > 4096 {
		return nil, "", errors.New("archive resume key limit")
	}
	q := url.Values{"url": []string{original}, "output": []string{"json"}, "fl": []string{"timestamp,original,statuscode,mimetype,digest"}, "limit": []string{"50"}, "showResumeKey": []string{"true"}, "collapse": []string{"digest"}, "filter": []string{"statuscode:200"}, "matchType": []string{match}, "gzip": []string{"false"}}
	if stamp != "" {
		if !archiveTime.MatchString(stamp) {
			return nil, "", errors.New("invalid capture timestamp")
		}
		q.Set("to", stamp)
		q.Set("limit", "-50")
	}
	if resume != "" {
		q.Set("resumeKey", resume)
	}
	out, e := a.Broker.Fetch(ctx, webacquire.Request{Method: "GET", URL: a.Base + "/cdx/search/cdx?" + q.Encode()})
	if e != nil {
		return nil, "", e
	}
	if out.Status != 200 {
		return nil, "", errors.New("archive index unavailable")
	}
	dec := json.NewDecoder(bytes.NewReader(out.Body))
	var rows [][]string
	if e = dec.Decode(&rows); e != nil {
		return nil, "", errors.New("invalid archive index")
	}
	if len(rows) > 51 {
		return nil, "", errors.New("archive index row limit")
	}
	captures := []Capture{}
	seen := map[string]bool{}
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) != 5 || !archiveTime.MatchString(row[0]) {
			return nil, "", errors.New("invalid archive capture row")
		}
		if stamp != "" && row[0] > stamp {
			continue
		}
		if a.original(row[1]) != nil {
			continue
		}
		key := row[1] + "\x00" + row[4]
		if seen[key] {
			continue
		}
		seen[key] = true
		status, e := strconv.Atoi(row[2])
		if e != nil {
			continue
		}
		captures = append(captures, Capture{Timestamp: row[0], Original: row[1], Status: status, MIME: row[3], Digest: row[4]})
	}
	next := ""
	var token any
	if dec.Decode(&token) == nil {
		switch x := token.(type) {
		case string:
			next = x
		case []any:
			if len(x) == 1 {
				next, _ = x[0].(string)
			}
		}
	}
	if len(next) > 4096 {
		return nil, "", errors.New("archive resume key limit")
	}
	return captures, next, nil
}
func (a *Archive) Fetch(ctx context.Context, c Capture) (webacquire.Response, error) {
	if !archiveTime.MatchString(c.Timestamp) {
		return webacquire.Response{}, errors.New("invalid capture timestamp")
	}
	if e := a.original(c.Original); e != nil {
		return webacquire.Response{}, e
	}
	out, e := a.Broker.Fetch(ctx, webacquire.Request{Method: "GET", URL: a.Base + "/web/" + c.Timestamp + "id_/" + c.Original})
	if e != nil {
		return out, e
	}
	if out.Status != 200 {
		return out, errors.New("archive body unavailable")
	}
	return out, nil
}
func (a *Archive) Closest(ctx context.Context, original, stamp string) (Capture, error) {
	rows, _, e := a.Query(ctx, original, "exact", stamp, "")
	if e != nil {
		return Capture{}, e
	}
	if len(rows) == 0 {
		return Capture{}, errors.New("no temporally relevant archived asset")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Timestamp > rows[j].Timestamp })
	return rows[0], nil
}
func (s *Service) archiveSeeds(ctx context.Context, targets []string) {
	if s.Archive == nil {
		s.gap("archive", "", "archive provider unavailable")
		return
	}
	for _, target := range targets {
		resume := s.Archive.Resume
		for page := 0; page < 3; page++ {
			captures, next, e := s.Archive.Query(ctx, target, "host", "", resume)
			if e != nil {
				s.gap("archive", target, "archive index unavailable or discovery denied")
				break
			}
			for _, c := range captures {
				kind := "script"
				if strings.Contains(c.MIME, "html") {
					kind = "page"
				}
				s.enqueue(ctx, frontier{URL: c.Original, Kind: kind, Timestamp: c.Timestamp})
			}
			if next == "" {
				break
			}
			resume = next
			if page == 2 {
				s.gap("archive", target, "archive pagination limit; resume key: "+resume)
			}
		}
	}
}
func (s *Service) archiveResponse(ctx context.Context, f frontier) (webacquire.Response, string, error) {
	if s.Archive == nil {
		return webacquire.Response{}, "", errors.New("archive expansion unavailable")
	}
	c, e := s.Archive.Closest(ctx, f.URL, f.Timestamp)
	if e != nil {
		return webacquire.Response{}, "", e
	}
	out, e := s.Archive.Fetch(ctx, c)
	if c.Timestamp != f.Timestamp {
		s.gap("archive", f.URL, "reference uses an earlier capture: "+c.Timestamp)
	}
	out.FinalURL = c.Original
	return out, c.Timestamp, e
}
