// extsweep checks the browser extensions installed on this computer against
// a list of known malicious extensions and flags ones installed or built in
// risky ways.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

var version = "dev"

func main() {
	// Double clicking the exe opens a console that closes as soon as we exit.
	pause := ownsConsole()
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	if pause {
		fmt.Print("\n" + messages[detectLang()].pressEnter)
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("extsweep", flag.ContinueOnError)
	fl.SetOutput(stderr)
	jsonOut := fl.Bool("json", false, "print the report as JSON")
	all := fl.Bool("all", false, "also list every installed extension")
	minSev := fl.String("min", "low", "lowest severity to report: low, medium, high or critical")
	iocFile := fl.String("ioc", "", "extra list of bad extension ids, one per line (an optional name may follow the id)")
	update := fl.Bool("update", false, "download the latest known malicious list, then scan")
	updateTo := fl.String("update-to", "", "download the latest list into `file` and exit (for refreshing the built-in copy)")
	noCode := fl.Bool("no-code", false, "skip reading extension code, check ids, install source and permissions only")
	noColor := fl.Bool("no-color", false, "disable colored output")
	langFlag := fl.String("lang", "", "report language: en or tr (default: system language)")
	showVersion := fl.Bool("version", false, "print the version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: extsweep [flags] [browser-or-profile-folder ...]\n\n")
		fmt.Fprintf(stderr, "Finds every Chrome, Edge, Brave, Opera, Vivaldi, Arc and Firefox profile on\n")
		fmt.Fprintf(stderr, "this computer and checks its extensions. Give folders to scan only those.\n")
		fmt.Fprintf(stderr, "Nothing is sent anywhere unless you pass -update.\n\n")
		fl.PrintDefaults()
		fmt.Fprintf(stderr, "\nexit status: 0 nothing serious, 1 high or critical findings, 2 error\n")
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "extsweep", version)
		return 0
	}
	msg := messages[detectLang()]
	if *langFlag != "" {
		if msg = messages[strings.ToLower(*langFlag)]; msg == nil {
			fmt.Fprintf(stderr, "extsweep: unknown language %q (use en or tr)\n", *langFlag)
			return 2
		}
	}
	min, err := parseSeverity(*minSev)
	if err != nil {
		fmt.Fprintln(stderr, "extsweep:", err)
		return 2
	}
	if *updateTo != "" || *update {
		n, err := updateIOC(*updateTo)
		if err != nil {
			fmt.Fprintln(stderr, "extsweep: update:", err)
			return 2
		}
		if *updateTo != "" {
			fmt.Fprintf(stdout, "wrote %s with %d extension ids\n", *updateTo, n)
			return 0
		}
		fmt.Fprintf(stderr, "extsweep: list updated, %d known malicious ids\n", n)
	}
	db, err := loadIOC(*iocFile)
	if err != nil {
		fmt.Fprintln(stderr, "extsweep:", err)
		return 2
	}

	var profiles []Profile
	if fl.NArg() == 0 {
		profiles = discoverProfiles()
	} else {
		for _, a := range fl.Args() {
			abs, err := filepath.Abs(a)
			if err != nil || !isDir(abs) {
				fmt.Fprintf(stderr, "extsweep: %s is not a folder\n", a)
				return 2
			}
			found := profilesIn(guessBrowser(abs), abs, isFirefoxDir(abs))
			if len(found) == 0 {
				fmt.Fprintf(stderr, "extsweep: no browser profile found in %s\n", a)
				return 2
			}
			profiles = append(profiles, found...)
		}
	}

	r := scan(profiles, db, !*noCode)
	if fl.NArg() == 0 {
		r.Findings = append(r.Findings, checkPolicies(forcedInstalls(), db)...)
	}
	sortFindings(r.Findings)

	worst := severity(0)
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
		if f.Severity >= min {
			kept = append(kept, f)
		}
	}
	r.Findings = kept

	if *jsonOut {
		if err := printJSON(stdout, r, *all); err != nil {
			fmt.Fprintln(stderr, "extsweep:", err)
			return 2
		}
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" &&
			(forceColor() || stdout == os.Stdout && enableColor(os.Stdout))
		printText(stdout, r, *all, palette(color), msg)
	}
	if worst >= high {
		return 1
	}
	return 0
}

// scan reads every profile and runs the checks.
func scan(profiles []Profile, db *iocDB, codeScan bool) *Result {
	r := &Result{Profiles: profiles, Lists: db.sources}
	for _, p := range profiles {
		exts, err := readProfile(p)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("%s / %s: %v", p.Browser, p.Name, err))
		}
		for _, e := range exts {
			r.Extensions = append(r.Extensions, e)
			r.Findings = append(r.Findings, checkExtension(e, db, codeScan)...)
		}
	}
	return r
}

// guessBrowser names a folder given on the command line: a known browser
// folder gets its browser name, "User Data" gets its parent's name.
func guessBrowser(dir string) string {
	clean := strings.ToLower(filepath.Clean(dir))
	for _, d := range knownBrowserDirs() {
		known := strings.ToLower(filepath.Clean(d.path))
		if clean == known || strings.HasPrefix(clean, known+string(filepath.Separator)) {
			return d.name
		}
	}
	if strings.EqualFold(filepath.Base(dir), "User Data") {
		return filepath.Base(filepath.Dir(dir))
	}
	return filepath.Base(dir)
}

func isFirefoxDir(dir string) bool {
	if isFile(filepath.Join(dir, "prefs.js")) || isFile(filepath.Join(dir, "extensions.json")) {
		return true
	}
	return len(firefoxProfiles("", dir)) > 0 && !isChromiumProfile(dir)
}

func forceColor() bool {
	v := os.Getenv("CLICOLOR_FORCE")
	return v != "" && v != "0"
}

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}
