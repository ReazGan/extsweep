package main

import (
	"archive/zip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxCodeFiles = 400
	maxFileBytes = 6 << 20
	maxTotal     = 40 << 20
)

type codeHit struct {
	rule     string
	file     string
	evidence string
}

var (
	reTelegram    = regexp.MustCompile(`api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}`)
	reDiscordHook = regexp.MustCompile(`discord(?:app)?\.com/api/webhooks/[0-9]{15,}/[A-Za-z0-9_-]{30,}`)
	reObfuscator  = regexp.MustCompile(`_0x[0-9a-f]{4,6}`)
	reEvalLike    = regexp.MustCompile(`\beval\s*\(`)
	reRemoteJS    = regexp.MustCompile(`importScripts\s*\(\s*['"]https?://|<script[^>]+src\s*=\s*['"]https?://`)
	reFetch       = regexp.MustCompile(`\bfetch\s*\(|XMLHttpRequest|\$\.(?:ajax|get|post)\s*\(`)
	reCookiesAll  = regexp.MustCompile(`cookies\.getAll\s*\(`)
	reExternalURL = regexp.MustCompile(`https?://[a-z0-9.-]+\.[a-z]{2,}`)
)

// scanCode looks through an extension's scripts for a few strong signals:
// hard-coded exfiltration channels, code pulled from the network at run
// time, and javascript-obfuscator output. It returns at most one hit per rule.
func scanCode(e *Extension) []codeHit {
	found := map[string]codeHit{}
	visit := func(name string, data []byte) {
		if len(found) == 4 {
			return
		}
		text := string(data)
		lower := strings.ToLower(name)
		isHTML := strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm")
		if _, ok := found["EXT020"]; !ok {
			if m := reTelegram.FindString(text); m != "" {
				found["EXT020"] = codeHit{"EXT020", name, redactToken(m)}
			} else if m := reDiscordHook.FindString(text); m != "" {
				found["EXT020"] = codeHit{"EXT020", name, redactToken(m)}
			}
		}
		if _, ok := found["EXT021"]; !ok {
			if m := reRemoteJS.FindString(text); m != "" {
				found["EXT021"] = codeHit{"EXT021", name, m}
			} else if !isHTML && e.Manifest < 3 && reFetch.MatchString(text) {
				// Manifest V3 extension pages cannot eval at all, so this
				// only matters for V2 extensions.
				if at := evalOfData(text); at >= 0 {
					found["EXT021"] = codeHit{"EXT021", name, snippet(text, at)}
				}
			}
		}
		if _, ok := found["EXT022"]; !ok && !isHTML {
			if n := len(reObfuscator.FindAllStringIndex(text, 200)); n >= 200 {
				found["EXT022"] = codeHit{"EXT022", name, "javascript-obfuscator style names (_0x...)"}
			}
		}
		if _, ok := found["EXT023"]; !ok && !isHTML {
			if loc := reCookiesAll.FindStringIndex(text); loc != nil && reFetch.MatchString(text) && reExternalURL.MatchString(text) {
				found["EXT023"] = codeHit{"EXT023", name, snippet(text, loc[0])}
			}
		}
	}

	switch {
	case e.Dir != "" && isDir(e.Dir):
		walkDir(e.Dir, visit)
	case e.xpi != "":
		walkXPI(e.xpi, visit)
	}
	var out []codeHit
	for _, id := range []string{"EXT020", "EXT021", "EXT022", "EXT023"} {
		if h, ok := found[id]; ok {
			out = append(out, h)
		}
	}
	return out
}

// evalOfData returns the offset of the first eval whose argument is not a
// plain string literal, which is the shape of "download then run", or -1.
func evalOfData(text string) int {
	for _, loc := range reEvalLike.FindAllStringIndex(text, 50) {
		rest := strings.TrimLeft(text[loc[1]:min(len(text), loc[1]+80)], " \t\r\n")
		if rest == "" {
			continue
		}
		switch rest[0] {
		case '"', '\'', '`', ')':
			continue // eval("literal") or eval()
		}
		return loc[0]
	}
	return -1
}

func codeFile(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".js") || strings.HasSuffix(n, ".mjs") || strings.HasSuffix(n, ".html") || strings.HasSuffix(n, ".htm")
}

func walkDir(root string, visit func(string, []byte)) {
	files, total := 0, 0
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "_metadata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !codeFile(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes {
			return nil
		}
		if files >= maxCodeFiles || total >= maxTotal {
			return fs.SkipAll
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files++
		total += len(data)
		rel, _ := filepath.Rel(root, p)
		visit(filepath.ToSlash(rel), data)
		return nil
	})
}

func walkXPI(path string, visit func(string, []byte)) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return
	}
	defer zr.Close()
	files, total := 0, 0
	for _, f := range zr.File {
		if !codeFile(f.Name) || f.UncompressedSize64 > maxFileBytes {
			continue
		}
		if files >= maxCodeFiles || total >= maxTotal {
			return
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxFileBytes))
		rc.Close()
		if err != nil {
			continue
		}
		files++
		total += len(data)
		visit(f.Name, data)
	}
}

func snippet(text string, at int) string {
	start := at
	end := min(len(text), at+90)
	s := strings.Join(strings.Fields(text[start:end]), " ")
	return s
}

// redactToken keeps a webhook or bot url recognisable without printing the secret part.
func redactToken(s string) string {
	i := strings.LastIndexAny(s, ":/")
	if i < 0 || len(s)-i < 8 {
		return s
	}
	tail := s[i+1:]
	return s[:i+1] + tail[:4] + strings.Repeat("*", 8)
}
