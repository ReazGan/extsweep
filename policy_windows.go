//go:build windows

package main

import (
	"os/exec"
	"strings"
	"syscall"
)

var policyKeys = []struct{ browser, key string }{
	{"Chrome", `SOFTWARE\Policies\Google\Chrome`},
	{"Chromium", `SOFTWARE\Policies\Chromium`},
	{"Edge", `SOFTWARE\Policies\Microsoft\Edge`},
	{"Brave", `SOFTWARE\Policies\BraveSoftware\Brave`},
}

// forcedInstalls reads the extension policies from the registry, machine
// wide and for the current user.
func forcedInstalls() []forcedInstall {
	var out []forcedInstall
	for _, hive := range []string{"HKLM", "HKCU"} {
		for _, k := range policyKeys {
			base := hive + `\` + k.key
			for _, v := range regValues(base + `\ExtensionInstallForcelist`) {
				id, url := parseForcelistEntry(v)
				if looksLikeChromeID(id) {
					out = append(out, forcedInstall{k.browser, id, url, base + `\ExtensionInstallForcelist`})
				}
			}
			for _, v := range regNamed(base, "ExtensionSettings") {
				for _, p := range parseExtensionSettings(v) {
					out = append(out, forcedInstall{k.browser, p[0], p[1], base + `\ExtensionSettings`})
				}
			}
		}
	}
	return out
}

// regValues returns the data of every string value under a key.
func regValues(key string) []string {
	return parseRegQuery(runReg("query", key))
}

func regNamed(key, name string) []string {
	return parseRegQuery(runReg("query", key, "/v", name))
}

func runReg(args ...string) string {
	cmd := exec.Command("reg", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// parseRegQuery reads `reg query` output lines like
// "    1    REG_SZ    abcd...;https://example.com/update.xml".
func parseRegQuery(out string) []string {
	var vals []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, typ := range []string{"    REG_SZ    ", "    REG_EXPAND_SZ    "} {
			if i := strings.Index(line, typ); i >= 0 {
				vals = append(vals, strings.TrimSpace(line[i+len(typ):]))
			}
		}
	}
	return vals
}
