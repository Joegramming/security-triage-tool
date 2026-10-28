# File triage

Static check of files people send us (currently `.zip`) for risky structure: git repos with hooks/config, auto-run editor and AI-agent configs, executables, macro documents, traversal paths. It **never extracts or executes anything**: entries are read into memory with Python's `zipfile`, and nothing from the archive is ever run.

Built after a phishing zip containing a full Git repo whose `.git` hooks/config ran on the first `git` command (or on VS Code's automatic git status) and then spread to other local repos.

## Usage

Python 3.11+, standard library only.

```
python triage.py <file> [--json] [--virustotal] [--defender]
```

| Flag | Effect |
|---|---|
| `--json` | Machine-readable report (for the email pipeline later) |
| `--virustotal` | Looks up the archive's SHA256 on VirusTotal using `VT_API_KEY`. Lookup only, never uploads. |
| `--defender` | Windows: also runs `MpCmdRun.exe -Scan -ScanType 3 -File <path>`. Defender may quarantine the file. |

Exit codes: `0` nothing flagged, `1` findings, `2` error (missing file, unsupported type, crash).

Tests: `pip install pytest`, then `python -m pytest`.

## What it flags

**HIGH**: `.git` directories (also `.GIT.`, `GIT~1`, bare-repo layouts and `.git` gitdir-pointer files), non-`.sample` git hooks, dangerous `.git/config` keys (`core.fsmonitor`/`hooksPath`/`sshCommand`/`pager`/`editor`, `!` aliases, `url.*.insteadOf`, `credential.helper`, filters, textconv, `include.path`, …), `.vscode/tasks.json` with `runOn: folderOpen`, Claude/Gemini settings with hooks, Cursor rules that tell the agent to run commands, executables/scripts by extension, double extensions, bidi/RTL-override characters in names, macro Office files (`.docm`/`.xlsm`/`.pptm`/…, legacy `.doc`/`.xls`/`.ppt` with VBA, `vbaProject.bin` inside any OOXML file), path traversal / absolute paths, password-protected or unreadable entries (contents unknown), corrupted archives, zip-bomb caps exceeded, nested zips that couldn't be inspected (over the size cap, encrypted, unreadable, or more than 3 levels deep).

**MEDIUM**: npm `preinstall`/`install`/`postinstall`/`prepare` scripts, `.husky/` and `.githooks/`, MCP server configs, nested archives (nested zips are scanned to depth 3 and their findings listed as `outer.zip!/inner/path`; other formats only listed), suspicious text (curl/wget piped to a shell or run via `bash -c "$(curl …)"` / `bash <(curl …)`, `powershell -enc`, `IEX`, `Invoke-WebRequest`, `eval(atob(…))`, base64 blobs of 300+ chars, `node -e`, `python -c`), files over the per-file cap, a requested `--virustotal`/`--defender` check that couldn't run (so a missing API key never looks like a clean result).

**INFO**: archive SHA256, size, entry counts, and SHA256 of every flagged file.

Caps (top of `triage.py`): 500 MiB decompressed per run, 50 MiB per file, 20,000 entries per run (nested zips included), nested-zip depth 3. Once the total cap is hit, contents stop being read but every remaining name is still checked.

## What it can't detect

- **No findings does not mean safe.** It's pattern matching, not analysis.
- Contents of `.7z`, `.rar`, `.tar`, `.gz` (listed only), encrypted entries, and files over the cap.
- Anything inside git objects/packs (compressed), so a malicious commit you'd get on checkout isn't seen.
- Obfuscated scripts that avoid the regexes, malicious code in normal source files (`.ts`, `.py`, `.sh`, …), and dependencies that are only referenced, not included.
- Risky configs not in the rule list (e.g. `.gitmodules`, `.gitattributes`, other agent-instruction files like `AGENTS.md`).
- Expect noise on real project zips: every `.js` file is HIGH by design.

## Adding a rule

All rules live in [rules.py](rules.py):

- Most changes are a one-line edit to a list or table at the top: `EXECUTABLE_EXTS`, `DANGEROUS_GIT_CONFIG`, `TEXT_PATTERNS`, etc.
- A new `TEXT_PATTERNS` entry needs an example in `test_every_text_pattern_still_matches_through_the_prefilter`. For speed, you can also give it keywords in `TEXT_PATTERN_KEYWORDS`: the regex only runs when one of them appears in the file. Without keywords it always runs. Keep every gap in a pattern bounded (`{0,200}`, never `*`), because the input is hostile.
- For new logic, add a function decorated with `@rule`. It receives an `Entry` with `.path`, `.parts` (normalized the way Windows resolves names), `.name`, `.ext`, `.data` (bytes, or `None` for directories and unread files), `.text` (decoded, or `None` for binaries) and `.git_depth` (how many leading path parts form the enclosing git dir, or `None`), and yields `Finding(severity, reason)`. Pass `path=` to flag a folder instead of the file.
- Add a test in [test_triage.py](test_triage.py) that builds a harmless zip in memory. Fixture contents must be plain text that only looks like the pattern, never a real payload.

```python
@rule
def gitmodules(e):
    if e.name == ".gitmodules":
        yield Finding(MEDIUM, "Submodule config: can pull extra repos on clone --recursive")
```
