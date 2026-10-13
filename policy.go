package main

import (
	"encoding/json"
	"strings"
)

// forcedInstall is one extension a browser policy installs and keeps
// installed. Companies use this; so does adware, because the user cannot
// remove such an extension from the browser.
type forcedInstall struct {
	Browser   string `json:"browser"`
	ID        string `json:"id"`
	UpdateURL string `json:"update_url,omitempty"`
	Where     string `json:"where"`
}

var officialUpdateHosts = []string{
	"clients2.google.com/service/update2/crx",
	"edge.microsoft.com/extensionwebstorebase/",
	"extension-updates.opera.com/",
	"addons.mozilla.org/",
}

func officialUpdateURL(u string) bool {
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return true // no update url means the default store
	}
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	for _, h := range officialUpdateHosts {
		if strings.HasPrefix(u, h) {
			return true
		}
	}
	return false
}

// parseForcelistEntry splits "id;update_url" (the update url is optional).
func parseForcelistEntry(s string) (id, url string) {
	id, url, _ = strings.Cut(strings.TrimSpace(s), ";")
	return strings.ToLower(strings.TrimSpace(id)), strings.TrimSpace(url)
}

// parseExtensionSettings reads the ExtensionSettings policy (a JSON object
// keyed by extension id) and returns the force installed entries.
func parseExtensionSettings(raw string) [][2]string {
	var m map[string]struct {
		Mode      string `json:"installation_mode"`
		UpdateURL string `json:"update_url"`
	}
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	var out [][2]string
	for id, s := range m {
		if id == "*" {
			continue
		}
		if s.Mode == "force_installed" || s.Mode == "normal_installed" {
			out = append(out, [2]string{strings.ToLower(id), s.UpdateURL})
		}
	}
	return out
}

// policyJSON pulls forced installs out of one JSON policy document (Linux
// managed policy files and converted macOS plists share this shape).
func policyJSON(browser, where string, raw []byte) []forcedInstall {
	var doc struct {
		Forcelist []string        `json:"ExtensionInstallForcelist"`
		Settings  json.RawMessage `json:"ExtensionSettings"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []forcedInstall
	for _, entry := range doc.Forcelist {
		id, url := parseForcelistEntry(entry)
		if looksLikeChromeID(id) {
			out = append(out, forcedInstall{browser, id, url, where})
		}
	}
	if len(doc.Settings) > 0 {
		for _, p := range parseExtensionSettings(string(doc.Settings)) {
			out = append(out, forcedInstall{browser, p[0], p[1], where})
		}
	}
	return out
}
