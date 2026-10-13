//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
)

// forcedInstalls reads managed browser policies: plist files on macOS and
// JSON files under /etc on Linux.
func forcedInstalls() []forcedInstall {
	var out []forcedInstall
	if runtime.GOOS == "darwin" {
		domains := map[string]string{
			"com.google.Chrome": "Chrome", "org.chromium.Chromium": "Chromium",
			"com.microsoft.Edge": "Edge", "com.brave.Browser": "Brave",
		}
		dirs := []string{"/Library/Managed Preferences"}
		if u, err := user.Current(); err == nil {
			dirs = append(dirs, filepath.Join("/Library/Managed Preferences", u.Username))
		}
		for _, dir := range dirs {
			for domain, browser := range domains {
				p := filepath.Join(dir, domain+".plist")
				if !isFile(p) {
					continue
				}
				raw, err := exec.Command("plutil", "-convert", "json", "-o", "-", p).Output()
				if err == nil {
					out = append(out, policyJSON(browser, p, raw)...)
				}
			}
		}
		return out
	}
	dirs := map[string]string{
		"/etc/opt/chrome/policies/managed":       "Chrome",
		"/etc/chromium/policies/managed":         "Chromium",
		"/etc/opt/edge/policies/managed":         "Edge",
		"/etc/brave/policies/managed":            "Brave",
		"/etc/chromium-browser/policies/managed": "Chromium",
	}
	for dir, browser := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			if raw, err := os.ReadFile(f); err == nil {
				out = append(out, policyJSON(browser, f, raw)...)
			}
		}
	}
	return out
}
