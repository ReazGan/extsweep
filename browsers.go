package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Profile is one browser profile with its own set of extensions.
type Profile struct {
	Browser string `json:"browser"`
	Name    string `json:"profile"`
	Path    string `json:"path"`
	Firefox bool   `json:"-"`
}

type browserDir struct {
	name    string
	path    string // Chromium "User Data" dir, or a single profile dir (Opera), or a Firefox Profiles dir
	firefox bool
}

// knownBrowserDirs lists where each browser keeps its profiles on this OS.
func knownBrowserDirs() []browserDir {
	home, _ := os.UserHomeDir()
	var dirs []browserDir
	add := func(name, path string, ff bool) {
		if path != "" {
			dirs = append(dirs, browserDir{name, path, ff})
		}
	}
	switch runtime.GOOS {
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		roaming := os.Getenv("APPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		if roaming == "" {
			roaming = filepath.Join(home, "AppData", "Roaming")
		}
		l := func(p ...string) string { return filepath.Join(append([]string{local}, p...)...) }
		r := func(p ...string) string { return filepath.Join(append([]string{roaming}, p...)...) }
		add("Chrome", l("Google", "Chrome", "User Data"), false)
		add("Chrome Beta", l("Google", "Chrome Beta", "User Data"), false)
		add("Chrome Dev", l("Google", "Chrome Dev", "User Data"), false)
		add("Chrome Canary", l("Google", "Chrome SxS", "User Data"), false)
		add("Chromium", l("Chromium", "User Data"), false)
		add("Edge", l("Microsoft", "Edge", "User Data"), false)
		add("Edge Beta", l("Microsoft", "Edge Beta", "User Data"), false)
		add("Edge Dev", l("Microsoft", "Edge Dev", "User Data"), false)
		add("Brave", l("BraveSoftware", "Brave-Browser", "User Data"), false)
		add("Vivaldi", l("Vivaldi", "User Data"), false)
		add("Yandex", l("Yandex", "YandexBrowser", "User Data"), false)
		add("Opera", r("Opera Software", "Opera Stable"), false)
		add("Opera GX", r("Opera Software", "Opera GX Stable"), false)
		add("Firefox", r("Mozilla", "Firefox", "Profiles"), true)
		add("LibreWolf", r("librewolf", "Profiles"), true)
		add("Zen", r("zen", "Profiles"), true)
		if m, _ := filepath.Glob(l("Packages", "TheBrowserCompany.Arc_*", "LocalCache", "Local", "Arc", "User Data")); len(m) > 0 {
			add("Arc", m[0], false)
		}
	case "darwin":
		as := filepath.Join(home, "Library", "Application Support")
		a := func(p ...string) string { return filepath.Join(append([]string{as}, p...)...) }
		add("Chrome", a("Google", "Chrome"), false)
		add("Chrome Beta", a("Google", "Chrome Beta"), false)
		add("Chrome Canary", a("Google", "Chrome Canary"), false)
		add("Chromium", a("Chromium"), false)
		add("Edge", a("Microsoft Edge"), false)
		add("Brave", a("BraveSoftware", "Brave-Browser"), false)
		add("Vivaldi", a("Vivaldi"), false)
		add("Arc", a("Arc", "User Data"), false)
		add("Yandex", a("Yandex", "YandexBrowser"), false)
		add("Opera", a("com.operasoftware.Opera"), false)
		add("Opera GX", a("com.operasoftware.OperaGX"), false)
		add("Firefox", a("Firefox", "Profiles"), true)
		add("LibreWolf", a("librewolf", "Profiles"), true)
		add("Zen", a("zen", "Profiles"), true)
	default:
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" {
			cfg = filepath.Join(home, ".config")
		}
		c := func(p ...string) string { return filepath.Join(append([]string{cfg}, p...)...) }
		h := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }
		add("Chrome", c("google-chrome"), false)
		add("Chrome Beta", c("google-chrome-beta"), false)
		add("Chrome Dev", c("google-chrome-unstable"), false)
		add("Chromium", c("chromium"), false)
		add("Chromium (snap)", h("snap", "chromium", "common", "chromium"), false)
		add("Chrome (flatpak)", h(".var", "app", "com.google.Chrome", "config", "google-chrome"), false)
		add("Chromium (flatpak)", h(".var", "app", "org.chromium.Chromium", "config", "chromium"), false)
		add("Edge", c("microsoft-edge"), false)
		add("Edge Beta", c("microsoft-edge-beta"), false)
		add("Brave", c("BraveSoftware", "Brave-Browser"), false)
		add("Brave (flatpak)", h(".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser"), false)
		add("Vivaldi", c("vivaldi"), false)
		add("Opera", c("opera"), false)
		add("Yandex", c("yandex-browser"), false)
		add("Firefox", h(".mozilla", "firefox"), true)
		add("Firefox (snap)", h("snap", "firefox", "common", ".mozilla", "firefox"), true)
		add("Firefox (flatpak)", h(".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"), true)
		add("LibreWolf", h(".librewolf"), true)
		add("Zen", h(".zen"), true)
	}
	return dirs
}

// discoverProfiles finds every profile of every installed browser.
func discoverProfiles() []Profile {
	var out []Profile
	for _, d := range knownBrowserDirs() {
		out = append(out, profilesIn(d.name, d.path, d.firefox)...)
	}
	return out
}

// profilesIn lists the profiles under one browser directory. It also accepts
// a single profile directory, which is how Opera lays things out.
func profilesIn(browser, dir string, firefox bool) []Profile {
	if !isDir(dir) {
		return nil
	}
	if firefox {
		return firefoxProfiles(browser, dir)
	}
	if isChromiumProfile(dir) {
		return []Profile{{Browser: browser, Name: filepath.Base(dir), Path: dir}}
	}
	names := chromiumProfileNames(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Profile
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n := e.Name()
		if n == "System Profile" || n == "Guest Profile" {
			continue
		}
		p := filepath.Join(dir, n)
		if !isChromiumProfile(p) {
			continue
		}
		label := n
		if friendly := names[n]; friendly != "" && friendly != n {
			label = n + " (" + safeText(friendly) + ")"
		}
		out = append(out, Profile{Browser: browser, Name: label, Path: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func isChromiumProfile(dir string) bool {
	return isFile(filepath.Join(dir, "Secure Preferences")) || isFile(filepath.Join(dir, "Preferences"))
}

// chromiumProfileNames reads the profile names the user sees from "Local State".
func chromiumProfileNames(userData string) map[string]string {
	raw, err := os.ReadFile(filepath.Join(userData, "Local State"))
	if err != nil {
		return nil
	}
	var ls struct {
		Profile struct {
			InfoCache map[string]struct {
				Name string `json:"name"`
			} `json:"info_cache"`
		} `json:"profile"`
	}
	if json.Unmarshal(raw, &ls) != nil {
		return nil
	}
	out := map[string]string{}
	for dir, info := range ls.Profile.InfoCache {
		out[dir] = strings.TrimSpace(info.Name)
	}
	return out
}

func firefoxProfiles(browser, dir string) []Profile {
	if isFile(filepath.Join(dir, "extensions.json")) || isFile(filepath.Join(dir, "prefs.js")) {
		return []Profile{{Browser: browser, Name: filepath.Base(dir), Path: dir, Firefox: true}}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Profile
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() && (isFile(filepath.Join(p, "extensions.json")) || isFile(filepath.Join(p, "prefs.js"))) {
			out = append(out, Profile{Browser: browser, Name: e.Name(), Path: p, Firefox: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
