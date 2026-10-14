package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Install sources, from most to least trusted.
const (
	srcStore       = "store"        // installed from the browser's extension store
	srcExternal    = "external"     // installed by another program on this computer
	srcPolicy      = "policy"       // forced by a browser policy
	srcUnpacked    = "unpacked"     // loaded from a folder in developer mode
	srcCommandLine = "command-line" // loaded with --load-extension when the browser started
	srcSideloaded  = "sideloaded"   // Firefox: placed there by another program
	srcTemporary   = "temporary"    // Firefox: loaded through about:debugging
	srcUnknown     = "unknown"
)

// Extension is one installed extension in one profile.
type Extension struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Browser     string    `json:"browser"`
	Profile     string    `json:"profile"`
	Dir         string    `json:"path,omitempty"`
	Enabled     bool      `json:"enabled"`
	Source      string    `json:"source"`
	UpdateURL   string    `json:"update_url,omitempty"`
	Installed   time.Time `json:"installed,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	Hosts       []string  `json:"hosts,omitempty"`
	Manifest    int       `json:"manifest_version,omitempty"`
	Unsigned    bool      `json:"unsigned,omitempty"`
	Firefox     bool      `json:"-"`
	OnDiskOnly  bool      `json:"on_disk_only,omitempty"`

	xpi string // Firefox package path, read lazily for code checks
}

// Chromium's ManifestLocation values (extensions/common/mojom/manifest.mojom).
const (
	locInternal          = 1
	locExternalPref      = 2
	locExternalRegistry  = 3
	locUnpacked          = 4
	locComponent         = 5
	locExternalPrefDL    = 6
	locExternalPolicyDL  = 7
	locCommandLine       = 8
	locExternalPolicy    = 9
	locExternalComponent = 10
)

type manifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	ManifestVersion int               `json:"manifest_version"`
	DefaultLocale   string            `json:"default_locale"`
	UpdateURL       string            `json:"update_url"`
	Permissions     []json.RawMessage `json:"permissions"`
	HostPermissions []string          `json:"host_permissions"`
	ContentScripts  []struct {
		Matches []string `json:"matches"`
	} `json:"content_scripts"`
	Browser struct {
		Gecko struct {
			ID string `json:"id"`
		} `json:"gecko"`
	} `json:"browser_specific_settings"`
}

type chromeSetting struct {
	Location         int             `json:"location"`
	Path             string          `json:"path"`
	State            *int            `json:"state"`
	DisableReasons   json.RawMessage `json:"disable_reasons"`
	FromWebstore     bool            `json:"from_webstore"`
	FirstInstallTime string          `json:"first_install_time"`
	InstallTime      string          `json:"install_time"`
	Manifest         json.RawMessage `json:"manifest"`
	ActivePerms      *struct {
		API            []json.RawMessage `json:"api"`
		ExplicitHost   []string          `json:"explicit_host"`
		ScriptableHost []string          `json:"scriptable_host"`
	} `json:"active_permissions"`
}

// readProfile returns every user-installed extension in a profile.
func readProfile(p Profile) ([]*Extension, error) {
	if p.Firefox {
		return readFirefox(p)
	}
	return readChromium(p)
}

func readChromium(p Profile) ([]*Extension, error) {
	settings := map[string]chromeSetting{}
	var lastErr error
	// Preferences first, Secure Preferences wins where both have an entry.
	for _, fn := range []string{"Preferences", "Secure Preferences"} {
		raw, err := os.ReadFile(filepath.Join(p.Path, fn))
		if err != nil {
			if !os.IsNotExist(err) {
				lastErr = err
			}
			continue
		}
		var doc struct {
			Extensions struct {
				Settings map[string]json.RawMessage `json:"settings"`
			} `json:"extensions"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			lastErr = err
			continue
		}
		for id, rawSet := range doc.Extensions.Settings {
			var s chromeSetting
			if json.Unmarshal(rawSet, &s) == nil && (s.Location != 0 || s.Path != "") {
				settings[id] = s
			}
		}
	}
	extRoot := filepath.Join(p.Path, "Extensions")
	var out []*Extension
	seen := map[string]bool{}
	for id, s := range settings {
		if s.Location == locComponent || s.Location == locExternalComponent {
			continue // part of the browser itself
		}
		e := &Extension{ID: id, Browser: p.Browser, Profile: p.Name, Source: chromiumSource(s), Enabled: chromiumEnabled(s)}
		if s.Path != "" {
			if filepath.IsAbs(s.Path) {
				e.Dir = s.Path
			} else {
				e.Dir = filepath.Join(extRoot, filepath.FromSlash(strings.ReplaceAll(s.Path, "\\", "/")))
			}
		}
		e.Installed = chromeTime(s.FirstInstallTime, s.InstallTime)
		var m manifest
		mdir := ""
		if e.Dir != "" {
			if raw, err := os.ReadFile(filepath.Join(e.Dir, "manifest.json")); err == nil && json.Unmarshal(stripBOM(raw), &m) == nil {
				mdir = e.Dir
			}
		}
		if mdir == "" && len(s.Manifest) > 0 {
			_ = json.Unmarshal(s.Manifest, &m)
		}
		applyManifest(e, m, mdir)
		// Edge marks its own store installs from_webstore=false; the update
		// url still says where it came from.
		if s.Location == locInternal && e.Source == srcExternal && storeHosted(e) {
			e.Source = srcStore
		}
		if s.ActivePerms != nil {
			e.Permissions = apiNames(s.ActivePerms.API)
			e.Hosts = uniq(append(append([]string{}, s.ActivePerms.ExplicitHost...), s.ActivePerms.ScriptableHost...))
		}
		if e.Name == "" {
			e.Name = id
		}
		seen[id] = true
		out = append(out, e)
	}
	// Folders in Extensions that the browser does not list. The browser
	// does not load these, but a known bad id here still means something
	// dropped it on the machine.
	if entries, err := os.ReadDir(extRoot); err == nil {
		for _, d := range entries {
			id := d.Name()
			if !d.IsDir() || seen[id] || !looksLikeChromeID(id) {
				continue
			}
			e := &Extension{ID: id, Name: id, Browser: p.Browser, Profile: p.Name, Source: srcUnknown, OnDiskOnly: true}
			if vers, _ := os.ReadDir(filepath.Join(extRoot, id)); len(vers) > 0 {
				e.Dir = filepath.Join(extRoot, id, vers[len(vers)-1].Name())
				var m manifest
				if raw, err := os.ReadFile(filepath.Join(e.Dir, "manifest.json")); err == nil && json.Unmarshal(stripBOM(raw), &m) == nil {
					applyManifest(e, m, e.Dir)
				}
			}
			out = append(out, e)
		}
	}
	sortExtensions(out)
	if len(settings) == 0 && lastErr != nil {
		return out, lastErr
	}
	return out, nil
}

func chromiumSource(s chromeSetting) string {
	switch s.Location {
	case locInternal:
		if s.FromWebstore {
			return srcStore
		}
		return srcExternal
	case locExternalPref, locExternalRegistry, locExternalPrefDL:
		if s.FromWebstore {
			return srcStore
		}
		return srcExternal
	case locExternalPolicy, locExternalPolicyDL:
		return srcPolicy
	case locUnpacked:
		return srcUnpacked
	case locCommandLine:
		return srcCommandLine
	}
	return srcUnknown
}

func chromiumEnabled(s chromeSetting) bool {
	if s.State != nil && *s.State == 0 {
		return false
	}
	r := strings.TrimSpace(string(s.DisableReasons))
	return r == "" || r == "null" || r == "[]" || r == "0"
}

// chromeTime parses Chrome's install time: microseconds since 1601-01-01 UTC.
func chromeTime(vals ...string) time.Time {
	for _, v := range vals {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		const epochDiff = 11644473600 // seconds between 1601 and 1970
		sec := n/1e6 - epochDiff
		if sec > 0 {
			return time.Unix(sec, (n%1e6)*1000).UTC()
		}
	}
	return time.Time{}
}

func applyManifest(e *Extension, m manifest, dir string) {
	if m.Version != "" {
		e.Version = m.Version
	}
	e.Manifest = m.ManifestVersion
	e.UpdateURL = m.UpdateURL
	if n := resolveMessage(m.Name, m.DefaultLocale, dir); n != "" {
		e.Name = n
	}
	e.Permissions = apiNames(m.Permissions)
	hosts := append([]string{}, m.HostPermissions...)
	for _, p := range e.Permissions {
		if looksLikeHost(p) {
			hosts = append(hosts, p)
		}
	}
	for _, cs := range m.ContentScripts {
		hosts = append(hosts, cs.Matches...)
	}
	e.Hosts = uniq(hosts)
	var apis []string
	for _, p := range e.Permissions {
		if !looksLikeHost(p) {
			apis = append(apis, p)
		}
	}
	e.Permissions = apis
}

// resolveMessage turns "__MSG_appName__" into the text from _locales.
func resolveMessage(name, locale, dir string) string {
	if !strings.HasPrefix(name, "__MSG_") || !strings.HasSuffix(name, "__") || dir == "" {
		return name
	}
	key := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__"))
	locales := []string{"en", "en_US", "en_GB"}
	if locale != "" {
		locales = append([]string{locale}, locales...)
	}
	for _, loc := range locales {
		raw, err := os.ReadFile(filepath.Join(dir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(stripBOM(raw), &msgs) != nil {
			continue
		}
		for k, v := range msgs {
			if strings.ToLower(k) == key && v.Message != "" {
				return v.Message
			}
		}
	}
	return ""
}

// apiNames flattens a permissions list; entries can be strings or objects.
func apiNames(raw []json.RawMessage) []string {
	var out []string
	for _, r := range raw {
		var s string
		if json.Unmarshal(r, &s) == nil {
			out = append(out, s)
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(r, &obj) == nil {
			for k := range obj {
				out = append(out, k)
			}
		}
	}
	return uniq(out)
}

// ---- Firefox ----

type ffAddon struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	Type           string `json:"type"`
	Active         bool   `json:"active"`
	UserDisabled   bool   `json:"userDisabled"`
	AppDisabled    bool   `json:"appDisabled"`
	Location       string `json:"location"`
	Path           string `json:"path"`
	SourceURI      string `json:"sourceURI"`
	SignedState    *int   `json:"signedState"`
	ForeignInstall bool   `json:"foreignInstall"`
	InstallDate    int64  `json:"installDate"`
	UpdateURL      string `json:"updateURL"`
	DefaultLocale  struct {
		Name string `json:"name"`
	} `json:"defaultLocale"`
	UserPermissions *struct {
		Permissions []string `json:"permissions"`
		Origins     []string `json:"origins"`
	} `json:"userPermissions"`
}

func readFirefox(p Profile) ([]*Extension, error) {
	raw, err := os.ReadFile(filepath.Join(p.Path, "extensions.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Addons []ffAddon `json:"addons"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []*Extension
	for _, a := range doc.Addons {
		if a.Type != "extension" || strings.HasPrefix(a.Location, "app-builtin") || strings.HasPrefix(a.Location, "app-system") {
			continue
		}
		e := &Extension{
			ID: a.ID, Name: a.DefaultLocale.Name, Version: a.Version, Browser: p.Browser, Profile: p.Name,
			Enabled: a.Active && !a.UserDisabled && !a.AppDisabled, Firefox: true, UpdateURL: a.UpdateURL,
		}
		switch {
		case a.Location == "app-temporary":
			e.Source = srcTemporary
		case a.ForeignInstall:
			e.Source = srcSideloaded
		case strings.HasPrefix(a.SourceURI, "https://addons.mozilla.org/"):
			e.Source = srcStore
		case a.Location == "app-profile":
			e.Source = srcExternal
		default:
			e.Source = srcUnknown
		}
		if a.SignedState != nil && *a.SignedState <= 0 && a.Location != "app-temporary" {
			e.Unsigned = true
		}
		if a.InstallDate > 0 {
			e.Installed = time.UnixMilli(a.InstallDate).UTC()
		}
		if a.UserPermissions != nil {
			for _, perm := range a.UserPermissions.Permissions {
				if looksLikeHost(perm) {
					e.Hosts = append(e.Hosts, perm)
				} else {
					e.Permissions = append(e.Permissions, perm)
				}
			}
			e.Hosts = uniq(append(e.Hosts, a.UserPermissions.Origins...))
			e.Permissions = uniq(e.Permissions)
		}
		if strings.HasSuffix(strings.ToLower(a.Path), ".xpi") {
			e.xpi = a.Path
			if e.Name == "" || len(e.Hosts) == 0 {
				fillFromXPI(e)
			}
		} else if a.Path != "" && isDir(a.Path) {
			e.Dir = a.Path
		}
		if e.Name == "" {
			e.Name = a.ID
		}
		out = append(out, e)
	}
	sortExtensions(out)
	return out, nil
}

func fillFromXPI(e *Extension) {
	zr, err := zip.OpenReader(e.xpi)
	if err != nil {
		return
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return
		}
		defer rc.Close()
		var m manifest
		buf := make([]byte, 0, f.UncompressedSize64)
		tmp := make([]byte, 32*1024)
		for {
			n, err := rc.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil || len(buf) > 2<<20 {
				break
			}
		}
		if json.Unmarshal(stripBOM(buf), &m) == nil {
			name := e.Name
			applyManifest(e, m, "")
			if name != "" || strings.HasPrefix(e.Name, "__MSG_") {
				e.Name = name
			}
		}
		return
	}
}

// ---- helpers ----

func looksLikeHost(p string) bool {
	return p == "<all_urls>" || strings.Contains(p, "://") || strings.HasPrefix(p, "*.")
}

func looksLikeChromeID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if c < 'a' || c > 'p' {
			return false
		}
	}
	return true
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortExtensions(es []*Extension) {
	sort.SliceStable(es, func(i, j int) bool {
		if !strings.EqualFold(es[i].Name, es[j].Name) {
			return strings.ToLower(es[i].Name) < strings.ToLower(es[j].Name)
		}
		return es[i].ID < es[j].ID
	})
}

// safeText drops control characters and bidi overrides from text that comes
// from outside: extension names, versions, URLs, registry values, the bad
// list. A malicious extension could otherwise put terminal escape codes in
// its name and rewrite or hide lines of the report.
func safeText(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if !unsafeRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

// sanitize cleans every outside string on an extension before it is reported.
func (e *Extension) sanitize() {
	e.ID, e.Name, e.Version = safeText(e.ID), safeText(e.Name), safeText(e.Version)
	e.UpdateURL, e.Profile, e.Browser = safeText(e.UpdateURL), safeText(e.Profile), safeText(e.Browser)
	for i := range e.Permissions {
		e.Permissions[i] = safeText(e.Permissions[i])
	}
	for i := range e.Hosts {
		e.Hosts[i] = safeText(e.Hosts[i])
	}
}
