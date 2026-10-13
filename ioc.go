package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Known malicious extension ids from chrome-mal-ids by The Privacy Commons
// Institute (CC BY 4.0). Refresh with: extsweep -update
//
//go:embed ioc.tsv.gz
var embeddedIOC []byte

const iocSource = "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list-meta.csv"

type iocEntry struct {
	Name   string `json:"name,omitempty"`
	Threat string `json:"threat,omitempty"`
	Added  string `json:"reported,omitempty"`
	Ref    string `json:"reference,omitempty"`
	Origin string `json:"list"`
	// Weak means only an automated list calls it adware or a search
	// hijacker and the store still has it. Some of these are mainstream
	// extensions that simply change the default search engine.
	Weak bool `json:"weak,omitempty"`
}

type iocDB struct {
	entries map[string]iocEntry
	sources []string // "built in (2026-10-13, 7782 ids)" and similar, for the report
}

func (db *iocDB) lookup(id string) (iocEntry, bool) {
	e, ok := db.entries[strings.ToLower(id)]
	return e, ok
}

// loadIOC reads the built-in list, a newer downloaded copy if there is one,
// and an optional user list with one id per line.
func loadIOC(extra string) (*iocDB, error) {
	db := &iocDB{entries: map[string]iocEntry{}}
	n, err := db.addTSV(bytes.NewReader(embeddedIOC), "built-in")
	if err != nil {
		return nil, fmt.Errorf("built-in list: %w", err)
	}
	db.sources = append(db.sources, fmt.Sprintf("chrome-mal-ids (%d)", n))
	if p := cachedIOCPath(); p != "" {
		if f, err := os.Open(p); err == nil {
			n, err := db.addTSV(f, "updated")
			f.Close()
			if err == nil {
				st, _ := os.Stat(p)
				db.sources = append(db.sources, fmt.Sprintf("chrome-mal-ids %s (%d)", st.ModTime().Format("2006-01-02"), n))
			}
		}
	}
	if extra != "" {
		f, err := os.Open(extra)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		n := 0
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			id, name, _ := strings.Cut(line, " ")
			db.entries[strings.ToLower(id)] = iocEntry{Name: strings.TrimSpace(name), Origin: "your list"}
			n++
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
		db.sources = append(db.sources, fmt.Sprintf("%s (%d)", extra, n))
	}
	return db, nil
}

func (db *iocDB) addTSV(r io.Reader, origin string) (int, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		for len(f) < 6 {
			f = append(f, "")
		}
		db.entries[strings.ToLower(f[0])] = iocEntry{Name: f[1], Threat: f[2], Added: f[3], Ref: f[4], Origin: origin, Weak: f[5] == "weak"}
		n++
	}
	return n, sc.Err()
}

func cachedIOCPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "extsweep", "ioc.tsv.gz")
}

// updateIOC downloads the current list and stores it next to the built-in one.
func updateIOC(dest string) (int, error) {
	if dest == "" {
		dest = cachedIOCPath()
		if dest == "" {
			return 0, fmt.Errorf("no cache folder on this system")
		}
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(iocSource)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download failed: %s", resp.Status)
	}
	var buf bytes.Buffer
	n, err := convertIOC(io.LimitReader(resp.Body, 64<<20), &buf)
	if err != nil {
		return 0, err
	}
	if n < 1000 {
		return 0, fmt.Errorf("the downloaded list has only %d ids, keeping the old one", n)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, err
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp, dest)
}

// convertIOC turns the chrome-mal-ids CSV into the compact gzipped TSV.
func convertIOC(in io.Reader, out io.Writer) (int, error) {
	br := bufio.NewReader(in)
	if b, err := br.Peek(3); err == nil && bytes.Equal(b, []byte{0xEF, 0xBB, 0xBF}) {
		br.Discard(3) // a BOM in front of the first quote breaks the header
	}
	r := csv.NewReader(br)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	head, err := r.Read()
	if err != nil {
		return 0, err
	}
	bom := string(rune(0xFEFF))
	col := map[string]int{}
	for i, h := range head {
		col[strings.TrimPrefix(h, bom)] = i
	}
	for _, need := range []string{"EXTID", "EXTID-NAME", "DATE-ADD", "THREAT-TYPE", "ARTICLE", "SOURCE"} {
		if _, ok := col[need]; !ok {
			return 0, fmt.Errorf("column %s missing, the list format changed", need)
		}
	}
	clean := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ", bom, "")
	get := func(rec []string, k string) string {
		i, ok := col[k]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(clean.Replace(rec[i]))
	}
	rows := map[string]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		id := strings.ToLower(get(rec, "EXTID"))
		if !looksLikeChromeID(id) || get(rec, "CONFIRM-MAL") == "0" {
			continue
		}
		name := get(rec, "EXTID-NAME")
		if strings.EqualFold(name, "unknown") {
			name = ""
		}
		threat := strings.ToLower(get(rec, "THREAT-TYPE"))
		if threat == "unknown" {
			threat = ""
		}
		ref := get(rec, "ARTICLE")
		if !strings.HasPrefix(ref, "http") {
			ref = get(rec, "SOURCE")
		}
		if !strings.HasPrefix(ref, "http") {
			ref = ""
		}
		tier := "strong"
		if weakEntry(get(rec, "SOURCE"), get(rec, "ADD-SOURCES"), threat, get(rec, "STILL-ACTIVE"), get(rec, "TPCI-BEHAVIORAL")) {
			tier = "weak"
		}
		rows[id] = strings.Join([]string{id, name, threat, get(rec, "DATE-ADD"), ref, tier}, "\t")
	}
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	fmt.Fprintln(zw, "# chrome-mal-ids by The Privacy Commons Institute, CC BY 4.0")
	fmt.Fprintln(zw, "# https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids")
	fmt.Fprintln(zw, "# id\tname\tthreat\treported\treference\ttier")
	for _, id := range ids {
		fmt.Fprintln(zw, rows[id])
	}
	return len(ids), zw.Close()
}

// weakEntry marks ids whose only source is the automated
// malicious_extension_sentry feed, that it files under adware, search
// hijacking or nothing at all, and that are still listed in the store.
// Anything from a researcher write-up, removed from the store, or tagged
// as data theft stays strong.
func weakEntry(source, more, threat, active, behavior string) bool {
	if !strings.Contains(source, "malicious_extension_sentry") || strings.TrimSpace(more) != "" {
		return false
	}
	if active == "0" || strings.EqualFold(behavior, "malicious") {
		return false
	}
	for _, t := range strings.Split(threat, ",") {
		switch strings.TrimSpace(t) {
		case "", "adware", "browser-hijack":
		default:
			return false
		}
	}
	return true
}
