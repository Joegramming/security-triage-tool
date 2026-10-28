#!/usr/bin/env python3
"""Static triage of files people send us (currently .zip). Never extracts or executes anything.

Usage:      python triage.py <file> [--json] [--virustotal] [--defender]
Exit codes: 0 = nothing flagged, 1 = findings, 2 = error
Rules live in rules.py.
"""
import argparse
import glob
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict
from pathlib import Path

import rules
from rules import HIGH, MEDIUM, Entry, Finding

MAX_TOTAL_BYTES = 500 * 2**20  # everything decompressed in one run, nested archives included
MAX_FILE_BYTES = 50 * 2**20    # content read per entry
MAX_ENTRIES = 20_000           # per run, nested archives included (per archive would multiply with nesting)
MAX_DEPTH = 3                  # nested zips
COLLAPSE_AT = 5                # text report: more findings than this with the same reason become one line
DISCLAIMER = "No findings does not mean safe. Never open repos received as files; fresh-clone from a GitHub link instead."


class Scan:
    """Findings plus the decompression and entry budgets shared by one run."""

    def __init__(self):
        self.findings: list[Finding] = []
        self._seen = set()
        self.entries = 0
        self.bytes_read = 0
        self.capped = False
        # always present so --json keeps one shape; None when the archive couldn't be opened
        self.stats = dict.fromkeys(("files", "directories", "compressed_bytes", "uncompressed_bytes_declared"))

    def add(self, f: Finding):
        key = (f.severity, f.path, f.reason)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(f)


def read_entry(zf, info, scan, where):
    """Read one entry into memory, within the caps. Returns (data, too_big); data is None if it can't or
    shouldn't be read. Over-cap files are reported by the oversized_file rule, which knows the file type."""
    if scan.capped:
        return None, False
    try:
        with zf.open(info) as f:
            data = f.read(MAX_FILE_BYTES + 1)
    except Exception as exc:  # bad CRC, corrupt stream, unsupported compression, overlapping entries: flag, don't crash
        # HIGH like encrypted entries: contents are unknown, and a deliberately broken CRC must not
        # downgrade e.g. a folderOpen tasks.json that some extractors still write to disk
        scan.add(Finding(HIGH, f"Could not read entry ({type(exc).__name__}: {exc}): contents unknown", where))
        return None, False
    scan.bytes_read += len(data)
    if scan.bytes_read > MAX_TOTAL_BYTES:
        scan.capped = True
        scan.add(Finding(HIGH, f"Total uncompressed size passed the {MAX_TOTAL_BYTES // 2**20} MiB cap (possible zip bomb): "
                               "stopped reading contents, remaining entries checked by name only", where))
        return None, False
    if len(data) > MAX_FILE_BYTES:
        return None, True
    return data, False


def looks_like_zip(source):
    """zipfile.is_zipfile, except that input which makes it raise counts as a zip, so it gets opened and
    flagged as corrupted instead of crashing the scan (a crafted end record gives ValueError: negative seek)."""
    try:
        return zipfile.is_zipfile(source)
    except Exception:
        return True


def unicode_path_name(info):
    """Name from an Info-ZIP Unicode Path extra field (0x7075). Parsed here because Python 3.11's zipfile
    ignores it and 3.12+ ignores it when its checksum doesn't match, while other tools (e.g. 7-Zip) may use it."""
    extra = info.extra
    while len(extra) >= 4:
        kind, size = struct.unpack("<HH", extra[:4])
        if kind == 0x7075 and size > 5 and extra[4] == 1:  # version 1, then CRC32 of the plain name, then UTF-8
            return extra[9:4 + size].decode("utf-8", "replace")
        extra = extra[4 + size:]
    return None


def scan_zip(source, scan, label, prefix="", depth=0):
    """Run every rule on every entry of the zip at `source` (path or file object), recursing into nested zips."""
    if scan.entries >= MAX_ENTRIES:  # opening it would still parse its whole file list
        scan.add(Finding(HIGH, f"Over {MAX_ENTRIES:,} entries in total (nested zips included): not scanned, contents unknown", label))
        return
    try:
        zf = zipfile.ZipFile(source)
    except Exception as exc:  # BadZipFile, or whatever a malformed header triggers: flag, don't crash
        scan.add(Finding(HIGH, f"Corrupted or invalid zip archive ({exc})", label))
        return
    with zf:
        infos = zf.infolist()
        if depth == 0:
            scan.stats = {
                "files": sum(not i.is_dir() for i in infos),
                "directories": sum(i.is_dir() for i in infos),
                "compressed_bytes": sum(i.compress_size for i in infos),
                "uncompressed_bytes_declared": sum(i.file_size for i in infos),
            }
        budget = max(MAX_ENTRIES - scan.entries, 0)
        if len(infos) > budget:
            scan.add(Finding(HIGH, f"Over {MAX_ENTRIES:,} entries in total (nested zips included): {len(infos) - budget:,} "
                                   "entries here were not checked (possible zip bomb)", label))
            infos = infos[:budget]
        scan.entries += len(infos)
        # An entry can carry several names: the plain header name, a Unicode-path extra field, or a name zipfile
        # cut at a NUL byte. Tools disagree on which they use, so every rule checks all of them.
        named = []
        for info in infos:
            names = list(dict.fromkeys(n.replace("\\", "/") for n in
                                       (info.filename, info.orig_filename, unicode_path_name(info)) if n))
            named += [(info, n) for n in names]
            if len(names) > 1:
                scan.add(Finding(HIGH, f"Entry has more than one name ({', '.join(map(repr, names))}): extraction "
                                       "tools disagree on which one they write, so all of them are checked",
                                 prefix + names[-1]))
        stubs = [Entry(name) for _, name in named]
        rules.annotate_git_dirs(stubs)
        encrypted = sum(info.flag_bits & 0x1 for info in infos)
        for (info, _), stub in zip(named, stubs):
            data, too_big = None, False
            if not info.flag_bits & 0x1 and not stub.is_dir:
                data, too_big = read_entry(zf, info, scan, prefix + stub.path)
            entry = Entry(stub.path, data, stub.git_depth, is_symlink=stat.S_ISLNK(info.external_attr >> 16),
                          too_big=too_big)
            for f in rules.run_rules(entry):
                if not f.path:
                    f.path, f.sha256 = entry.path, entry.sha256
                f.path = prefix + f.path
                scan.add(f)
            # is_zipfile finds the archive from its end, like zip tools do, so junk prepended to a zip
            # (or a zip appended to an image or .exe) can't hide it
            if data and (entry.ext == ".zip" or looks_like_zip(io.BytesIO(data))):
                if depth < MAX_DEPTH:
                    scan_zip(io.BytesIO(data), scan, prefix + entry.path, prefix + entry.path + "!/", depth + 1)
                else:
                    scan.add(Finding(HIGH, f"Nested zip more than {MAX_DEPTH} levels deep: not scanned, contents unknown",
                                     prefix + entry.path, entry.sha256))
        if encrypted:
            scan.add(Finding(HIGH, f"Password-protected archive: {encrypted} encrypted entr{'y' if encrypted == 1 else 'ies'} "
                                   "could not be inspected (a common way to slip malware past scanners)", label))
        scan_joined_archive(zf, infos, scan, label, prefix, depth)


def scan_joined_archive(zf, infos, scan, label, prefix, depth):
    """zipfile reads the last archive in a file; some tools show the first. Scan whatever sits in front."""
    start = min((i.header_offset for i in infos), default=0)
    if start == 0 or scan.capped:
        return
    if start > MAX_FILE_BYTES:  # reading only part of it would hide a front archive without a trace
        scan.add(Finding(HIGH, f"Over {MAX_FILE_BYTES // 2**20} MiB of data in front of the archive: not inspected "
                               "(could be another archive that some tools show instead)", label))
        return
    zf.fp.seek(0)
    head = zf.fp.read(start)
    scan.bytes_read += len(head)
    if looks_like_zip(io.BytesIO(head)):
        scan.add(Finding(HIGH, "Two zip archives joined into one file: tools disagree on which one they show "
                               "(the first one's findings are listed under (first archive)!/)", label))
        if depth < MAX_DEPTH:
            scan_zip(io.BytesIO(head), scan, label + " (first archive)", prefix + "(first archive)!/", depth + 1)
        else:
            scan.add(Finding(HIGH, f"Joined archives more than {MAX_DEPTH} levels deep: the first one was not scanned, "
                                   "contents unknown", label))


def check_did_not_run(scan, label, note):
    """A check the user asked for that didn't run must not look like a clean result (exit 0)."""
    scan.add(Finding(MEDIUM, f"Requested check did not run: {note}", label))
    return note


def virustotal_lookup(sha256, scan, label):
    """Hash lookup only; the file is never uploaded."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        return check_did_not_run(scan, label, "VirusTotal: skipped, VT_API_KEY is not set")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            stats = json.load(resp)["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "VirusTotal: hash not known (new files are not known either; this is not a sign of safety)"
        return check_did_not_run(scan, label, f"VirusTotal: lookup failed (HTTP {exc.code})")
    except (OSError, ValueError, KeyError) as exc:
        return check_did_not_run(scan, label, f"VirusTotal: lookup failed ({exc})")
    malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
    if malicious or suspicious:
        scan.add(Finding(HIGH, f"VirusTotal: {malicious} engines flag this archive as malicious, {suspicious} as suspicious", label))
    return f"VirusTotal: {malicious} malicious, {suspicious} suspicious, {stats.get('undetected', 0)} undetected"


def defender_scan(path, scan):
    if sys.platform != "win32":
        return check_did_not_run(scan, path.name, "Defender: skipped (Windows only)")
    candidates = sorted(glob.glob(os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe")),
                        key=os.path.getmtime, reverse=True)
    candidates.append(os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"))
    exe = next((c for c in candidates if os.path.isfile(c)), None)
    if not exe:
        return check_did_not_run(scan, path.name, "Defender: skipped, MpCmdRun.exe not found")
    try:
        proc = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", str(path.resolve())],
                              capture_output=True, text=True, errors="replace", timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return check_did_not_run(scan, path.name, f"Defender: scan failed ({exc})")
    output = " | ".join(line.strip() for line in proc.stdout.splitlines() if line.strip())[-300:]
    if proc.returncode == 2:
        scan.add(Finding(HIGH, f"Microsoft Defender detected a threat: {output}", path.name))
        return "Defender: threat found"
    if proc.returncode == 0:
        return "Defender: no threats found"
    return check_did_not_run(scan, path.name, f"Defender: scan failed (exit {proc.returncode}): {output}")


def triage(path: Path, virustotal=False, defender=False) -> dict:
    scan = Scan()
    size = path.stat().st_size  # read before Defender runs: it may quarantine (delete) the file
    with path.open("rb") as f:
        sha256 = hashlib.file_digest(f, "sha256").hexdigest()
    scan_zip(path, scan, path.name)
    notes = []
    if virustotal:
        notes.append(virustotal_lookup(sha256, scan, path.name))
    if defender:
        notes.append(defender_scan(path, scan))
    order = {HIGH: 0, MEDIUM: 1}
    findings = sorted(scan.findings, key=lambda f: order[f.severity])  # stable: archive order within a severity
    return {"file": str(path), "sha256": sha256, "size_bytes": size, **scan.stats,
            "findings": [asdict(f) for f in findings], "notes": notes, "disclaimer": DISCLAIMER}


def printable(s: str) -> str:
    """Escape control and bidi characters so a hostile name can't reorder or hide text in the terminal."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)


def render_text(report: dict) -> str:
    out = [f"Triage report: {printable(report['file'])}"]
    for sev in (HIGH, MEDIUM):
        group = [f for f in report["findings"] if f["severity"] == sev]
        if not group:
            continue
        by_reason = {}
        for f in group:
            by_reason.setdefault(f["reason"], []).append(f)
        out += ["", f"{sev} ({len(group)})"]
        # Individual findings first: hundreds of identical ".js" lines must not bury a git hook below them
        for f in group:
            if len(by_reason[f["reason"]]) <= COLLAPSE_AT:
                out += [f"  {printable(f['path'])}", f"      {printable(f['reason'])}"]
                if f["sha256"]:
                    out.append(f"      sha256 {f['sha256']}")
        for reason, same in by_reason.items():
            if len(same) > COLLAPSE_AT:
                examples = ", ".join(printable(f["path"]) for f in same[:3])
                out += [f"  {len(same):,} entries: {printable(reason)}",
                        f"      e.g. {examples}, ... (every path and SHA256 is in --json)"]
    if not report["findings"]:
        out += ["", "No HIGH or MEDIUM findings."]
    out += ["", "INFO", f"  Archive SHA256: {report['sha256']}", f"  Archive size: {report['size_bytes']:,} bytes"]
    if report["files"] is not None:
        out += [f"  Entries: {report['files']:,} files, {report['directories']:,} folders",
                f"  Uncompressed size (declared in headers): {report['uncompressed_bytes_declared']:,} bytes"]
    out += [f"  {printable(n)}" for n in report["notes"]]
    out += ["", DISCLAIMER]
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Static triage of received files (.zip). Never extracts or executes anything.")
    parser.add_argument("file")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--virustotal", action="store_true", help="look up the archive's SHA256 on VirusTotal (VT_API_KEY; never uploads)")
    parser.add_argument("--defender", action="store_true", help="also scan the archive with Microsoft Defender (Windows)")
    args = parser.parse_args(argv)
    path = Path(args.file)
    if not path.is_file():
        print(f"error: {args.file} is not a file", file=sys.stderr)
        return 2
    if path.suffix.lower() != ".zip" and not looks_like_zip(path):
        print("error: unsupported file type; only .zip archives are supported for now", file=sys.stderr)
        return 2
    try:
        report = triage(path, args.virustotal, args.defender)
    except Exception as exc:  # exit 1 means "findings", so any crash must surface as 2
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else render_text(report))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")  # cp1252 consoles can't print every file name
    sys.exit(main())
