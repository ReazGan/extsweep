package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type palette bool

func (p palette) paint(code, s string) string {
	if !p {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

var sevColor = map[severity]string{critical: "1;31", high: "31", medium: "33", low: "36"}

const wrapWidth = 78

// Result is everything one run found.
type Result struct {
	Profiles   []Profile    `json:"profiles"`
	Extensions []*Extension `json:"extensions"`
	Findings   []Finding    `json:"findings"`
	Lists      []string     `json:"lists"`
	Errors     []string     `json:"errors,omitempty"`
}

type extGroup struct {
	ext      *Extension
	worst    severity
	findings []Finding
}

func printJSON(w io.Writer, r *Result, all bool) error {
	out := struct {
		Tool       string       `json:"tool"`
		Version    string       `json:"version"`
		Profiles   []Profile    `json:"profiles"`
		Scanned    int          `json:"extensions_scanned"`
		Lists      []string     `json:"lists"`
		Findings   []Finding    `json:"findings"`
		Extensions []*Extension `json:"extensions,omitempty"`
		Errors     []string     `json:"errors,omitempty"`
	}{"extsweep", version, r.Profiles, len(r.Extensions), r.Lists, r.Findings, nil, r.Errors}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	if all {
		out.Extensions = r.Extensions
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printText(w io.Writer, r *Result, all bool, color palette, msg *catalog) {
	fmt.Fprintln(w, color.paint("1", "extsweep")+"  "+msg.scanning)
	fmt.Fprintln(w)
	if len(r.Profiles) == 0 {
		fmt.Fprintln(w, msg.noBrowsers)
		return
	}

	byProfile := map[string][]*extGroup{}
	groupOf := map[*Extension]*extGroup{}
	var policy []Finding
	for _, f := range r.Findings {
		if f.Ext == nil {
			policy = append(policy, f)
			continue
		}
		g := groupOf[f.Ext]
		if g == nil {
			g = &extGroup{ext: f.Ext}
			groupOf[f.Ext] = g
			key := f.Ext.Browser + "\x00" + f.Ext.Profile
			byProfile[key] = append(byProfile[key], g)
		}
		g.findings = append(g.findings, f)
		if f.Severity > g.worst {
			g.worst = f.Severity
		}
	}

	anyCritical := false
	for _, p := range r.Profiles {
		groups := byProfile[p.Browser+"\x00"+p.Name]
		var listing []*Extension
		if all {
			for _, e := range r.Extensions {
				if e.Browser == p.Browser && e.Profile == p.Name {
					listing = append(listing, e)
				}
			}
		}
		if len(groups) == 0 && len(listing) == 0 {
			continue
		}
		fmt.Fprintln(w, color.paint("1", p.Browser+" / "+p.Name))
		sort.SliceStable(groups, func(i, j int) bool { return groups[i].worst > groups[j].worst })
		var lows []string
		for _, g := range groups {
			if g.worst == critical {
				anyCritical = true
			}
			if g.worst == low {
				for _, f := range g.findings {
					line := g.ext.Name + ": " + msg.rules[f.Rule].title
					if f.Detail != "" {
						line += " (" + f.Detail + ")"
					}
					lows = append(lows, line)
				}
				continue
			}
			printGroup(w, g, color, msg)
		}
		if len(lows) > 0 {
			fmt.Fprintln(w, "  "+color.paint("2", msg.alsoLow))
			for _, l := range lows {
				writeWrapped(w, l, "    - ", "      ")
			}
			fmt.Fprintln(w)
		}
		if all {
			for _, e := range listing {
				state := msg.sources[e.Source]
				if !e.Enabled && !e.OnDiskOnly {
					state += ", " + msg.disabled
				}
				fmt.Fprintf(w, "    %s %s  %s  (%s)\n", e.Name, e.Version, color.paint("2", e.ID), state)
			}
			fmt.Fprintln(w)
		}
	}

	if len(policy) > 0 {
		fmt.Fprintln(w, color.paint("1", msg.policyGroup))
		for _, f := range policy {
			if f.Severity == critical {
				anyCritical = true
			}
			rt := msg.rules[f.Rule]
			label := fmt.Sprintf("%-8s", msg.sev[f.Severity])
			fmt.Fprintf(w, "  %s %s: %s\n", color.paint(sevColor[f.Severity], label), f.Policy.Browser, f.Policy.ID)
			if f.IOC != nil {
				writeWrapped(w, msg.rules["EXT001"].title+iocLine(f.IOC, msg), "           ", "           ")
			}
			if f.Policy.UpdateURL != "" {
				writeWrapped(w, "update: "+f.Policy.UpdateURL, "           ", "           ")
			}
			writeWrapped(w, f.Policy.Where, "           ", "           ")
			if f.Severity >= high {
				writeWrapped(w, rt.what, "           ", "           ")
				writeWrapped(w, rt.todo, "           ", "           ")
			}
		}
		fmt.Fprintln(w)
	}

	flagged := 0
	for _, e := range r.Extensions {
		if groupOf[e] != nil {
			flagged++
		}
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, color.paint("32", msg.clean))
	} else if rest := len(r.Extensions) - flagged; rest > 0 {
		fmt.Fprintln(w, msg.plural(msg.cleanExt, msg.cleanExt1, rest))
	}
	fmt.Fprintf(w, msg.scanned+"\n", len(r.Extensions), msg.plural(msg.profileCount, msg.profileCount1, len(r.Profiles)), browserNames(r.Profiles))
	fmt.Fprintf(w, msg.listsUsed+"\n", strings.Join(r.Lists, ", "))
	for _, e := range r.Errors {
		fmt.Fprintln(w, color.paint("33", "! "+e))
	}
	if anyCritical {
		fmt.Fprintln(w)
		fmt.Fprintln(w, color.paint("1", msg.nextSteps))
		for i, s := range msg.steps {
			writeWrapped(w, s, fmt.Sprintf("  %d. ", i+1), "     ")
		}
	}
}

func printGroup(w io.Writer, g *extGroup, color palette, msg *catalog) {
	e := g.ext
	label := fmt.Sprintf("%-8s", msg.sev[g.worst])
	head := e.Name
	if e.Version != "" {
		head += "  " + e.Version
	}
	fmt.Fprintf(w, "  %s %s\n", color.paint(sevColor[g.worst], label), color.paint("1", head))
	meta := msg.id + " " + e.ID + ", " + msg.source + ": " + msg.sources[e.Source]
	if e.OnDiskOnly {
		meta += ", " + msg.notLoaded
	} else if !e.Enabled {
		meta += ", " + msg.disabled
	}
	writeWrapped(w, color.paint("2", meta), "           ", "           ")
	sort.SliceStable(g.findings, func(i, j int) bool { return g.findings[i].Severity > g.findings[j].Severity })
	for _, f := range g.findings {
		rt := msg.rules[f.Rule]
		title := rt.title
		if f.Detail != "" {
			title += " (" + f.Detail + ")"
		}
		fmt.Fprintln(w)
		writeWrapped(w, color.paint(sevColor[f.Severity], "* ")+title, "           ", "             ")
		writeWrapped(w, rt.what, "             ", "             ")
		if f.IOC != nil {
			writeWrapped(w, strings.TrimPrefix(iocLine(f.IOC, msg), ", "), "             ", "             ")
		}
		if f.File != "" {
			writeWrapped(w, msg.file+": "+f.File+"  "+f.Evidence, "             ", "             ")
		}
		writeWrapped(w, rt.todo, "             ", "             ")
	}
	fmt.Fprintln(w)
}

func iocLine(i *iocEntry, msg *catalog) string {
	var parts []string
	if i.Name != "" {
		parts = append(parts, `"`+i.Name+`"`)
	}
	if i.Threat != "" {
		parts = append(parts, msg.threat+": "+strings.ReplaceAll(i.Threat, ",", ", "))
	}
	if i.Added != "" {
		parts = append(parts, msg.reported+": "+i.Added)
	}
	if i.Ref != "" {
		parts = append(parts, msg.ref+": "+i.Ref)
	}
	if len(parts) == 0 {
		return ""
	}
	return ", " + strings.Join(parts, ", ")
}

func browserNames(ps []Profile) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if !seen[p.Browser] {
			seen[p.Browser] = true
			out = append(out, p.Browser)
		}
	}
	return strings.Join(out, ", ")
}

// writeWrapped prints text wrapped to wrapWidth with a first-line prefix and
// an indent for the following lines. ANSI codes are not counted.
func writeWrapped(w io.Writer, text, first, rest string) {
	words := strings.Fields(text)
	if len(words) == 0 {
		return
	}
	line := first
	width := visibleLen(first)
	for i, word := range words {
		wl := visibleLen(word)
		if i > 0 && width+1+wl > wrapWidth {
			fmt.Fprintln(w, line)
			line, width = rest+word, visibleLen(rest)+wl
			continue
		}
		if i > 0 {
			line += " "
			width++
		}
		line += word
		width += wl
	}
	fmt.Fprintln(w, line)
}

func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == 0x1b:
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}
