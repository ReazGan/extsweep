# extsweep

[![CI](https://github.com/ReazGan/extsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/extsweep/actions/workflows/ci.yml)

Check the browser extensions on your computer for known malicious ones, and
for extensions that were installed or built in ways that skip the store.

Extensions get bought, hijacked, or published just to steal sessions. One
campaign ran for seven years and reached about 4 million browsers
([Koi](https://www.koi.ai/blog/4-million-browsers-infected-inside-shadypanda-7-year-malware-campaign)),
another one 7.8 million
([Koi](https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers)).
Few people ever look at what they have installed. extsweep finds every Chrome,
Edge, Brave, Opera, Vivaldi, Arc and Firefox profile on the machine and tells
you in plain words which extensions are known bad and which ones are set up in
a risky way.

Runs offline. Nothing leaves your machine unless you ask for a list update.

![extsweep finding a known malicious extension, a Telegram upload and a developer mode extension](https://raw.githubusercontent.com/ReazGan/extsweep/main/docs/screenshot.svg)

## Install

Download the binary for your system from
[Releases](https://github.com/ReazGan/extsweep/releases), or:

```
go install github.com/ReazGan/extsweep@latest
```

On Windows you can double click `extsweep.exe`. The window stays open until
you press Enter.

## Usage

```
extsweep                       scan every browser profile on this computer
extsweep -min high             only high and critical findings
extsweep -all                  also list every installed extension
extsweep -json                 machine-readable output
extsweep -update               download the latest known bad list, then scan
extsweep -ioc mylist.txt       add your own ids, one per line
extsweep "path/to/User Data"   scan one browser folder or profile
extsweep -lang tr              Turkish report (picked by default on a Turkish system)
```

Exit status is `0` when nothing serious turns up, `1` for high or critical
findings, and `2` on error.

## What it checks

1. Known malicious ids. 7,782 ids from the chrome-mal-ids list. Ids that only
   an automated feed calls adware or a search hijacker, and that are still in
   the store, are reported as medium instead of critical: a few mainstream
   extensions land there just for changing the default search engine.
2. How it was installed. Loaded with `--load-extension` (a ChromeLoader trick),
   loaded unpacked in developer mode, added by another program, forced by a
   browser policy (registry on Windows, managed preferences on macOS, `/etc`
   policies on Linux), updated from a server outside the store, unsigned or
   sideloaded Firefox add-ons.
3. What it can do. Read and change every site, the debugger permission,
   proxy, management (it can switch other extensions off), native messaging.
4. What its code does. Hard-coded Telegram bot or Discord webhook addresses,
   code downloaded and run at run time (Manifest V2 only, V3 cannot), output
   of javascript-obfuscator, reading every cookie while talking to a server.
5. Leftovers. A folder in the profile's `Extensions` directory that the browser
   does not list is reported only when its id is known bad.

It reports and never removes anything. A wide permission is not a verdict on
its own: an ad blocker needs every site. The report says when something is
normal for that kind of extension, and store extensions with wide access are
listed as low.

## The known bad list

Extension ids come from
[chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)
by The Privacy Commons Institute, licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The copy built into
the binary (`ioc.tsv.gz`) keeps only the id, name, threat type, report date and
reference, and adds the weak or strong mark described above. `extsweep -update`
downloads the current list into your user cache folder and uses it from then
on.

## License

MIT for the code. The bundled extension id list is CC BY 4.0, see above.
