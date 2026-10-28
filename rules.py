"""Detection rules for triage.py. All of them live in this file.

To add a rule: write a function that takes an Entry and yields Finding objects,
decorate it with @rule, and add a test. Extension lists, regexes and the git
config table are at the top, so most tweaks are a one-line edit.

Rules see entry.data = None for directories and for files that were encrypted,
unreadable or over the size cap, so name-based rules still run on those.
"""
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from functools import cached_property

HIGH, MEDIUM = "HIGH", "MEDIUM"

# --- Lists -------------------------------------------------------------------

EXECUTABLE_EXTS = {
    ".exe", ".dll", ".scr", ".lnk", ".iso", ".img", ".vhd", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar",
    # also run or mount on double-click in Windows
    ".com", ".pif", ".cpl", ".vbe", ".psm1", ".reg", ".chm", ".vhdx", ".msix", ".appx",
    # Excel add-in (code runs on open), ClickOnce apps, settings shortcuts that run commands, patches, script hosts
    ".xll", ".appref-ms", ".application", ".settingcontent-ms", ".msp", ".wsh",
}
# Explorer reads these just to show the folder, and they can point it at a remote server, which then receives
# your Windows login hash; no click needed (exploited from zips in 2025, CVE-2025-24054 via .library-ms)
WINDOWS_SHELL_EXTS = {".library-ms", ".searchconnector-ms", ".scf", ".url", ".website"}
NETWORK_PATH_RE = re.compile(r"\\\\[^\\\s]+\\|(?<![:\w])//[^/\s]+/|file:", re.I)  # \\server\, //server/, file:
MACRO_OFFICE_EXTS = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".ppam"}
LEGACY_OFFICE_EXTS = {".doc", ".xls", ".ppt"}
VBA_MARKER = "_VBA_PROJECT".encode("utf-16-le")  # OLE stream name present when a legacy Office file has macros
# File types that are big for normal reasons; over the size cap they stay MEDIUM. Anything else over the cap
# is HIGH, since padding a tasks.json or git config past the cap would otherwise hide it from its rule.
BIG_MEDIA_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".wav", ".flac", ".png", ".jpg", ".jpeg", ".gif",
                  ".webp", ".tif", ".tiff", ".psd", ".ai", ".glb", ".fbx", ".obj", ".blend", ".hdr", ".exr", ".ktx2",
                  ".pdf"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab"}
# Extensions attackers put before the real one: invoice.pdf.exe
DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv",
              ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".mov", ".zip", ".html", ".htm"}
UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
BIDI_CHARS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")
NPM_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
# Package-manager config keys that run a program on every command or install (file name -> key pattern).
# npm's ini parser trims all whitespace (incl. form feed, no-break space, BOM) and unquotes keys, so match all
# of it. Never \s*: with re.M it crosses newlines, and every line start would rescan all following blank lines.
LINE_SPACE = r"(?:[^\S\r\n]|\N{ZERO WIDTH NO-BREAK SPACE})*"  # whitespace except line breaks, plus BOM
PACKAGE_MANAGER_RUNNERS = {
    ".yarnrc.yml": re.compile("^" + LINE_SPACE + r"[\"']?(yarnPath|plugins)[\"']?" + LINE_SPACE + ":", re.M | re.I),
    ".yarnrc": re.compile("^" + LINE_SPACE + r"[\"']?(yarn-path)\b", re.M | re.I),
    ".npmrc": re.compile("^" + LINE_SPACE + r"[\"']?(script-shell|node-options|onload-script)[\"']?" + LINE_SPACE + "=",
                         re.M | re.I),
}

# (section, key) -> why it's dangerous. key "*" matches any key in that section.
# Aliases starting with "!" are handled in git_config() because they depend on the value.
DANGEROUS_GIT_CONFIG = {
    ("core", "fsmonitor"): "runs a program on almost every git command (incl. VS Code's background git status)",
    ("core", "hookspath"): "points git at hook scripts outside .git/hooks",
    ("core", "sshcommand"): "runs a program on fetch/push/clone",
    ("core", "pager"): "runs a program whenever git pages output",
    ("core", "editor"): "runs a program whenever git opens an editor",
    ("core", "gitproxy"): "runs a program for git:// connections",
    ("core", "askpass"): "runs a program when git asks for a password",
    ("sequence", "editor"): "runs a program during rebase",
    ("credential", "helper"): "runs a program that receives your git credentials",
    ("url", "insteadof"): "silently rewrites remote URLs",
    ("url", "pushinsteadof"): "silently rewrites push URLs",
    ("filter", "smudge"): "runs a program on checkout",
    ("filter", "clean"): "runs a program on git add/status",
    ("filter", "process"): "runs a long-lived program on checkout/add",
    ("diff", "textconv"): "runs a program on git diff/log",
    ("diff", "command"): "runs a program on git diff",
    ("merge", "driver"): "runs a program on merge",
    ("gpg", "program"): "runs a program on signing/verification",
    ("include", "path"): "pulls in another config file (can hide the dangerous keys elsewhere)",
    ("includeif", "path"): "pulls in another config file (can hide the dangerous keys elsewhere)",
    ("pager", "*"): "runs a program as pager for a git command",
}

# Input is hostile, so patterns must stay linear. Gaps are bounded ({0,200}): an unbounded [^\n]* rescans
# the rest of the line from every match start, so a few KB of compressed "curl curl ..." could stall the scan for hours.
TEXT_PATTERNS = {
    "curl/wget piped to a shell": re.compile(  # also | sudo -E bash, | /bin/bash
        r"\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo(\s+-\S+)*\s+)?([^\s|]{0,100}/)?(ba|z|da|k)?sh\b", re.I),
    # bash -c "$(curl ...)", bash <(curl ...); separate pattern + lookahead: 2x faster than one combined regex
    "shell running curl/wget output": re.compile(
        r"(?=[bzdks])\b(?:ba|z|da|k)?sh\b[^\n]{0,20}(?:\$\(|<\()\s*(?:curl|wget)\b", re.I),
    "PowerShell encoded command": re.compile(
        r"(^|\s)-(enc|encodedcommand)\b|\b(powershell|pwsh)(\.exe)?\b[^\n]{0,200}\s[-/]e[a-z]*\s+['\"]?[a-z0-9+/=]{16,}", re.I),
    "IEX / Invoke-Expression": re.compile(r"\b(iex|invoke-expression)\b", re.I),
    "Invoke-WebRequest / DownloadString": re.compile(r"\b(invoke-webrequest|downloadstring)\b", re.I),
    "eval(atob(...))": re.compile(r"\beval\s*\(\s*(window\.)?atob\s*\(", re.I),
    "long base64 blob": re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{300,}={0,2}"),  # lookbehind: only try at run starts
    "node -e": re.compile(r"\bnode(\.exe)?\s+(-e|--eval|-p|--print)\b", re.I),
    "python -c": re.compile(r"\b(python[0-9.]*|py)(\.exe)?\s+-c\b", re.I),
}
# Speed prefilter: a pattern only runs if one of its words is in the (lowercased) file.
# Patterns without an entry here always run. A wrong word here silently disables a pattern, so test each one.
TEXT_PATTERN_KEYWORDS = {
    "curl/wget piped to a shell": ("curl", "wget"),
    "shell running curl/wget output": ("curl", "wget"),
    "PowerShell encoded command": ("-enc", "powershell", "pwsh"),
    "IEX / Invoke-Expression": ("iex", "invoke-expression"),
    "Invoke-WebRequest / DownloadString": ("invoke-webrequest", "downloadstring"),
    "eval(atob(...))": ("atob",),
    "node -e": ("node",),
    "python -c": ("py",),
}
# re.I matches \u0130 and \u0131 as i and \u017f as s, but str.lower() doesn't: map them so the prefilter never skips a match
KEYWORD_FOLD = str.maketrans({"\u0130": "i", "\u0131": "i", "\u017f": "s"})
AGENT_RUN_RE = re.compile(
    r"\b(run|execute|exec|invoke|launch)\b[^\n]{0,60}"
    r"\b(command|script|shell|terminal|bash|cmd|powershell|pwsh|curl|wget|npm|npx|node|python)\b", re.I)
# Just the value: tasks.json allows comments, so "runOn": /* x */ "folderOpen" must still match
FOLDER_OPEN_RE = re.compile(r'"folderOpen"', re.I)
# Settings keys that make Claude Code or Gemini CLI run a command on their own, not just "hooks"
AGENT_COMMAND_KEYS_RE = re.compile(
    r"""["']?(hooks|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper"""
    r"""|toolDiscoveryCommand|toolCallCommand)["']?\s*[:=]""", re.I)
JSON_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
SHORT_NAME_RE = re.compile(r"[^.~]{1,6}~\d{1,6}(\.[^.]{0,3})?")  # 8.3 short name: up to 6 chars, ~N, optional 3-char ext
# Anchored with ^: used with .match() per line anyway, and this keeps them linear even under .search()
GIT_SECTION_RE = re.compile(r'^\s*\[\s*([^\]\s"]+)\s*(?:"(?:[^"\\]|\\.)*")?\s*\](.*)')
GIT_KEY_RE = re.compile(r"^\s*([A-Za-z][\w-]*)\s*(?:=\s*(.*)|[;#].*)?$")


# --- Model -------------------------------------------------------------------

@dataclass
class Finding:
    severity: str
    reason: str
    path: str = ""  # rules leave this empty to flag the entry itself; the scanner fills it in
    sha256: str | None = None


def norm_part(part: str) -> str:
    """Normalize a path part the way Windows resolves it: case-insensitive, trailing dots/spaces ignored, GIT~1 = .git,
    and NTFS stream syntax dropped (".vscode::$INDEX_ALLOCATION" is the .vscode folder itself)."""
    n = part.lower().split(":", 1)[0].rstrip(" .") or part
    return ".git" if re.fullmatch(r"git~\d+", n) else n


@dataclass
class Entry:
    path: str                   # path inside the archive, '/'-separated, original spelling
    data: bytes | None = None
    git_depth: int | None = None  # number of leading path parts forming the enclosing git dir, set by annotate_git_dirs()
    is_symlink: bool = False      # Unix symlink entry; its data is the link target
    too_big: bool = False         # over the per-file cap, so data is None and content rules can't run

    @cached_property
    def raw_parts(self) -> list[str]:
        return [p for p in self.path.split("/") if p]

    @cached_property
    def parts(self) -> list[str]:
        return [norm_part(p) for p in self.raw_parts]

    @property
    def is_dir(self) -> bool:
        return self.path.endswith("/")

    @cached_property
    def key(self) -> str:
        return "/".join(self.parts) + ("/" if self.is_dir else "")

    @property
    def name(self) -> str:
        return self.parts[-1] if self.parts else ""

    @property
    def ext(self) -> str:
        return posixpath.splitext(self.name)[1]

    @property
    def is_binary(self) -> bool:
        return bool(self.data) and self.data[:2] not in UTF16_BOMS and b"\0" in self.data[:8192]

    @cached_property
    def text(self) -> str | None:
        """Decoded content, None for empty or unread files. Deliberately not None for "binary" files:
        one NUL byte in a comment must not hide a tasks.json or git config from its rule."""
        d = self.data
        if not d:
            return None
        if d[:2] in UTF16_BOMS:
            return d.decode("utf-16", "replace")
        return d.decode("utf-8-sig", "replace")

    @cached_property
    def sha256(self) -> str | None:
        return None if self.data is None else hashlib.sha256(self.data).hexdigest()

    def dir_path(self, depth: int) -> str:
        """Original spelling of the first `depth` path parts, as a folder path."""
        return "".join(p + "/" for p in self.raw_parts[:depth]) or "(archive root)"


def annotate_git_dirs(entries: list[Entry]) -> None:
    """Set git_depth on entries inside anything git treats as a repository: a .git folder,
    or a bare-repo layout (HEAD + objects/ or refs/), which is how a .git file's gitdir: target looks.
    Folders get integer ids so hostile, very deep paths cost linear time instead of one string per prefix."""
    ids = {}               # (parent id, part) -> folder id; 0 is the archive root
    names = {0: ""}        # folder id -> its own name
    children = {0: set()}  # folder id -> names of its children, folders with a trailing "/"
    chains = []            # per entry: folder ids from the root down to its own folder
    for e in entries:
        fid, chain = 0, [0]
        for p in (e.parts if e.is_dir else e.parts[:-1]):
            children[fid].add(p + "/")
            fid = ids.setdefault((fid, p), len(ids) + 1)
            names.setdefault(fid, p)
            children.setdefault(fid, set())
            chain.append(fid)
        if not e.is_dir and e.parts:
            children[fid].add(e.parts[-1])
        chains.append(chain)
    # git itself needs HEAD + objects/ + refs/ and treats config as optional, so don't require config
    git = {fid for fid, c in children.items()
           if names[fid] == ".git" or "head" in c and ("objects/" in c or "refs/" in c)}
    for e, chain in zip(entries, chains):
        e.git_depth = max((depth for depth, fid in enumerate(chain) if fid in git), default=None)


def git_config_items(text: str):
    """Yield (section, key, value) from git config text; names lowercased, subsections dropped."""
    section = ""
    for line in text.splitlines():
        if m := GIT_SECTION_RE.match(line):
            section, line = m[1].lower().split(".")[0], m[2]  # [core] and legacy [url.foo] forms
        if section and (m := GIT_KEY_RE.match(line)):
            yield section, m[1].lower(), (m[2] or "").strip()


def unescape_json(text: str) -> str:
    """Undo \\uXXXX escapes so "run\\u004fn" can't dodge the regexes."""
    return JSON_ESCAPE_RE.sub(lambda m: chr(int(m[1], 16)), text)


def text_pattern_hits(text: str) -> list[str]:
    """Names of the TEXT_PATTERNS found in text; the keyword prefilter skips most regex passes on normal files."""
    folded = (text if text.isascii() else text.translate(KEYWORD_FOLD)).lower()
    return [name for name, rx in TEXT_PATTERNS.items()
            if (name not in TEXT_PATTERN_KEYWORDS or any(k in folded for k in TEXT_PATTERN_KEYWORDS[name]))
            and rx.search(text)]


# --- Rules -------------------------------------------------------------------

RULES = []


def rule(fn):
    RULES.append(fn)
    return fn


def run_rules(entry: Entry):
    for check in RULES:
        try:
            yield from check(entry)
        except Exception as exc:  # hostile content tripped a rule: report it and keep running the others
            yield Finding(MEDIUM, f"Rule {check.__name__} failed on this entry ({type(exc).__name__}); "
                                  "content may be crafted to break the scanner")


@rule
def path_traversal(e):
    if e.path.startswith("/") or re.match(r"[A-Za-z]:", e.path) or any(re.fullmatch(r"\s*\.{2,}\s*", p) for p in e.raw_parts):
        yield Finding(HIGH, "Path traversal or absolute path: extracting this would write outside the target folder")


@rule
def oversized_file(e):
    if e.too_big and e.ext in BIG_MEDIA_EXTS:
        yield Finding(MEDIUM, f"Larger than the per-file size cap ({e.ext}): content not inspected")
    elif e.too_big:
        yield Finding(HIGH, "Larger than the per-file size cap: contents unknown (padding can hide a config file "
                            "like tasks.json or .git/config from its rule)")


@rule
def windows_path_tricks(e):
    short = next((raw for raw, part in zip(e.raw_parts, e.parts) if SHORT_NAME_RE.fullmatch(part)), None)
    if short:
        yield Finding(HIGH, f"Windows 8.3 short name {short!r}: once the real folder exists, Windows can resolve this "
                            "to it (e.g. VSCODE~1 = .vscode), so files land in folders the other rules watch")
    if ":" in e.path:
        yield Finding(HIGH, "Colon in the name: NTFS stream syntax can name a folder itself "
                            "(.vscode::$INDEX_ALLOCATION = .vscode), or a drive")


@rule
def symlink(e):
    if e.is_symlink:
        yield Finding(HIGH, f"Symbolic link to {(e.text or '?')[:200]!r}: unzip on WSL, macOS or Linux creates it, "
                            "and later entries can then be written through it to anywhere on disk")


@rule
def bidi_characters(e):
    if any(c in BIDI_CHARS for c in e.path):
        yield Finding(HIGH, "Right-to-left override or other bidi control character in the name (hides the real extension)")


@rule
def git_repository(e):
    if (depth := e.git_depth) is not None:
        what = (".git directory: git commands run in this folder (including VS Code's automatic ones) obey its hooks and config"
                if depth and e.parts[depth - 1] == ".git" else
                "Bare git repository layout (HEAD with objects/ or refs/): git treats this folder as a repository")
        yield Finding(HIGH, what, path=e.dir_path(depth))
    if e.name == ".git" and not e.is_dir:
        yield Finding(HIGH, ".git file (gitdir: pointer): can redirect git to a repository hidden elsewhere")


@rule
def git_hooks(e):
    if e.git_depth is not None and not e.is_dir and e.parts[-2:-1] == ["hooks"] and not e.name.endswith(".sample"):
        yield Finding(HIGH, "Git hook script: runs automatically on git commands such as checkout, commit or merge")


@rule
def git_config(e):
    if e.git_depth is None or e.name not in ("config", "config.worktree") or not e.text:
        return
    for section, key, value in git_config_items(e.text):
        why = DANGEROUS_GIT_CONFIG.get((section, key)) or DANGEROUS_GIT_CONFIG.get((section, "*"))
        if section == "alias" and value.lstrip('"').startswith("!"):
            why = "shell alias: runs an arbitrary command when the alias is used"
        if why:
            yield Finding(HIGH, f"git config sets {section}.{key} = {value[:80]!r}: {why}")


@rule
def vscode_folder_open_task(e):
    if (("/" + e.key).endswith("/.vscode/tasks.json") or e.ext == ".code-workspace") and e.text \
            and FOLDER_OPEN_RE.search(unescape_json(e.text)):
        yield Finding(HIGH, 'VS Code task with "runOn": "folderOpen": runs a command as soon as the folder is opened')


@rule
def ai_agent_config(e):
    claude = e.parts[-2:] in ([".claude", "settings.json"], [".claude", "settings.local.json"])
    gemini = ".gemini" in e.parts[:-1]
    cursor = "/.cursor/rules/" in "/" + e.key or e.name == ".cursorrules"
    mcp = e.name == ".mcp.json" or e.parts[-2:] in ([".cursor", "mcp.json"], [".vscode", "mcp.json"])
    if not (claude or gemini or cursor or mcp) or not e.text:
        return  # check the path first: unescaping every text file costs seconds on escape-packed input
    text = unescape_json(e.text)
    if (claude or gemini) and (m := AGENT_COMMAND_KEYS_RE.search(text)):
        tool = "Claude Code settings" if claude else "Gemini CLI config"
        yield Finding(HIGH, f"{tool} with {m[1]!r}: runs shell commands automatically during an AI session")
    if cursor and (AGENT_RUN_RE.search(text) or text_pattern_hits(text)):
        yield Finding(HIGH, "Cursor rule file that tells the AI agent to run commands")
    if (mcp or gemini and '"mcpServers"' in text) and '"command"' in text:
        yield Finding(MEDIUM, "MCP server config: launches local commands when an AI tool opens this folder")


@rule
def executable(e):
    if not e.is_dir and e.ext in EXECUTABLE_EXTS:
        yield Finding(HIGH, f"Executable or script file type ({e.ext})")


@rule
def windows_shell_files(e):
    leak = "Explorer can contact a remote server just by showing the folder, sending it your Windows login hash"
    if not e.is_dir and e.ext in WINDOWS_SHELL_EXTS:
        yield Finding(HIGH, f"Windows shell file ({e.ext}): {leak}")
    elif e.name == "desktop.ini" and e.text and NETWORK_PATH_RE.search(e.text):
        yield Finding(HIGH, f"desktop.ini pointing at a network path: {leak}")


@rule
def double_extension(e):
    parts = e.name.rsplit(".", 2)
    if not e.is_dir and len(parts) == 3 and "." + parts[1].strip() in DECOY_EXTS and "." + parts[2] in EXECUTABLE_EXTS:
        yield Finding(HIGH, f"Double extension (.{parts[1].strip()}.{parts[2]}): executable disguised as a document")


@rule
def office_macros(e):
    if e.ext in MACRO_OFFICE_EXTS:
        yield Finding(HIGH, f"Macro-enabled Office file ({e.ext})")
    elif e.ext in LEGACY_OFFICE_EXTS and e.data and VBA_MARKER in e.data:
        yield Finding(HIGH, f"Legacy Office file ({e.ext}) containing a VBA macro project")
    elif e.name == "vbaproject.bin":
        yield Finding(HIGH, "VBA macro project inside an Office document")


@rule
def npm_lifecycle_scripts(e):
    if e.name != "package.json" or not e.text:
        return
    try:
        scripts = json.loads(e.text).get("scripts") or {}
        found = {k: v for k, v in scripts.items() if k in NPM_LIFECYCLE_SCRIPTS}
    except (ValueError, AttributeError, RecursionError):  # invalid, oddly shaped or absurdly nested JSON: text search
        names = "|".join(NPM_LIFECYCLE_SCRIPTS)
        found = {m[1]: "?" for m in re.finditer(rf'"({names})"\s*:', e.text)}
    if found:
        listed = "; ".join(f"{k}: {str(v)[:80]}" for k, v in found.items())
        yield Finding(MEDIUM, f"npm lifecycle script, runs automatically on npm install: {listed}")


@rule
def package_manager_configs(e):
    if e.is_dir:
        return
    if e.name in (".pnpmfile.cjs", ".pnpmfile.mjs"):
        yield Finding(MEDIUM, f"{e.name}: pnpm runs this code on every install")
    elif (rx := PACKAGE_MANAGER_RUNNERS.get(e.name)) and e.text and (m := rx.search(e.text)):
        yield Finding(MEDIUM, f"{e.name} sets {m[1]!r}: runs a program on every package-manager command")


@rule
def hook_manager_dirs(e):
    for i, part in enumerate(e.parts):
        if part in (".husky", ".githooks") and (i < len(e.parts) - 1 or e.is_dir):
            yield Finding(MEDIUM, f"{part}/ directory: git hooks that get activated by npm install (husky) or core.hooksPath",
                          path=e.dir_path(i + 1))
            return


@rule
def nested_archive(e):
    if e.is_dir or e.ext not in ARCHIVE_EXTS:
        return
    if e.ext != ".zip":  # only zips are opened; anything else could hide a whole repo
        yield Finding(HIGH, f"Nested archive ({e.ext}): contents not inspected, could hide anything")
    elif e.data is None:  # padding a nested zip past the size cap must not hide what's inside
        yield Finding(HIGH, "Nested zip that could not be inspected (too big, encrypted or unreadable): contents unknown")
    else:
        yield Finding(MEDIUM, "Nested archive (.zip); anything found inside is listed as this path + !/")


@rule
def suspicious_text(e):
    if not e.is_binary and e.text:  # the one rule that scans every file, so skip images, binaries, etc.
        if hits := text_pattern_hits(e.text):
            yield Finding(MEDIUM, "Suspicious content: " + ", ".join(hits))
