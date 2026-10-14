package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type severity int

const (
	low severity = iota + 1
	medium
	high
	critical
)

func (s severity) String() string {
	switch s {
	case critical:
		return "critical"
	case high:
		return "high"
	case medium:
		return "medium"
	case low:
		return "low"
	}
	return "unknown"
}

func (s severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func parseSeverity(s string) (severity, error) {
	switch strings.ToLower(s) {
	case "low":
		return low, nil
	case "medium":
		return medium, nil
	case "high":
		return high, nil
	case "critical":
		return critical, nil
	}
	return 0, fmt.Errorf("unknown severity %q (use low, medium, high or critical)", s)
}

// Finding is one problem with one extension, or with a browser policy.
type Finding struct {
	Rule     string         `json:"rule"`
	Severity severity       `json:"severity"`
	Ext      *Extension     `json:"extension,omitempty"`
	Policy   *forcedInstall `json:"policy,omitempty"`
	Detail   string         `json:"detail,omitempty"`
	File     string         `json:"file,omitempty"`
	Evidence string         `json:"evidence,omitempty"`
	IOC      *iocEntry      `json:"ioc,omitempty"`
}

var broadHosts = map[string]bool{
	"<all_urls>": true, "*://*/*": true, "http://*/*": true, "https://*/*": true,
	"*://*/": true, "http://*/": true, "https://*/": true, "*://*": true, "file:///*": false,
}

// hasBroadAccess is true when the extension can run on every website.
func hasBroadAccess(e *Extension) bool {
	for _, h := range e.Hosts {
		if broadHosts[h] {
			return true
		}
	}
	return false
}

var fullAccessPerms = []string{"cookies", "webRequest", "webRequestBlocking", "scripting", "declarativeNetRequestWithHostAccess", "proxy", "debugger"}

func hasPerm(e *Extension, name string) bool {
	for _, p := range e.Permissions {
		if p == name {
			return true
		}
	}
	return false
}

func fromStore(e *Extension) bool { return e.Source == srcStore }

// storeHosted is true when the extension updates from an official store.
func storeHosted(e *Extension) bool {
	return e.UpdateURL != "" && officialUpdateURL(e.UpdateURL)
}

// pick returns a when the extension came from a store, b otherwise.
func pick(e *Extension, store, other severity) severity {
	if fromStore(e) {
		return store
	}
	return other
}

// checkExtension runs every rule on one extension.
func checkExtension(e *Extension, db *iocDB, codeScan bool) []Finding {
	var out []Finding
	add := func(rule string, sev severity, detail string) {
		out = append(out, Finding{Rule: rule, Severity: sev, Ext: e, Detail: detail})
	}

	if hit, ok := db.lookup(e.ID); ok {
		h := hit
		if h.Weak {
			out = append(out, Finding{Rule: "EXT015", Severity: medium, Ext: e, IOC: &h})
		} else {
			out = append(out, Finding{Rule: "EXT001", Severity: critical, Ext: e, IOC: &h})
		}
	}
	if e.OnDiskOnly {
		// Not loaded by the browser; only a known bad id is worth reporting.
		return out
	}
	broad := hasBroadAccess(e)

	switch e.Source {
	case srcCommandLine:
		add("EXT002", high, "")
	case srcUnpacked:
		add("EXT004", map[bool]severity{true: high, false: medium}[broad], "")
	case srcExternal:
		// A program asked the browser to install a store extension (IDM,
		// antivirus suites do this). Worth knowing, not alarming.
		if storeHosted(e) {
			add("EXT005", low, "")
		} else {
			add("EXT005", map[bool]severity{true: high, false: medium}[broad], "")
		}
	case srcSideloaded:
		add("EXT007", map[bool]severity{true: high, false: medium}[broad], "")
	case srcTemporary:
		add("EXT009", low, "")
	}
	if e.Unsigned {
		add("EXT008", high, "")
	}
	if !officialUpdateURL(e.UpdateURL) && e.Source != srcUnpacked && e.Source != srcCommandLine && e.Source != srcPolicy {
		add("EXT006", high, e.UpdateURL)
	}

	if !e.Enabled {
		return out // a disabled extension cannot use its permissions
	}
	if broad {
		var strong []string
		for _, p := range fullAccessPerms {
			if hasPerm(e, p) {
				strong = append(strong, p)
			}
		}
		if len(strong) > 0 {
			add("EXT010", pick(e, low, medium), strings.Join(strong, ", "))
		}
	}
	if hasPerm(e, "debugger") {
		add("EXT011", pick(e, medium, high), "")
	}
	if hasPerm(e, "proxy") {
		add("EXT012", medium, "")
	}
	if hasPerm(e, "management") {
		add("EXT013", medium, "")
	}
	if hasPerm(e, "nativeMessaging") {
		add("EXT014", low, "")
	}

	if codeScan {
		for _, h := range scanCode(e) {
			sev := map[string]severity{
				"EXT020": high,
				"EXT021": pick(e, medium, high),
				"EXT022": medium,
				"EXT023": pick(e, medium, high),
			}[h.rule]
			out = append(out, Finding{Rule: h.rule, Severity: sev, Ext: e, File: safeText(h.file), Evidence: safeText(h.evidence)})
		}
	}
	return out
}

// checkPolicies reports forced installs. A force install pulled from a
// server other than an official store is how several adware families keep
// their extension on a machine.
func checkPolicies(forced []forcedInstall, db *iocDB) []Finding {
	var out []Finding
	for i := range forced {
		f := forced[i]
		f.ID, f.UpdateURL, f.Where = safeText(f.ID), safeText(f.UpdateURL), safeText(f.Where)
		var sev severity
		var ioc *iocEntry
		if hit, ok := db.lookup(f.ID); ok && !hit.Weak {
			h := hit
			sev, ioc = critical, &h
		} else if !officialUpdateURL(f.UpdateURL) {
			sev = high
		} else {
			sev = low
		}
		out = append(out, Finding{Rule: "EXT003", Severity: sev, Policy: &f, Detail: f.UpdateURL, IOC: ioc})
	}
	return out
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
}
