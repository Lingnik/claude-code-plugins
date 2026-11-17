#!/usr/bin/env python3
"""Secret matching for the gitleaks-redact hook.

Combines the vendored gitleaks default rules (gitleaks_rules.py) with a few
extra shapes for well-known public services, and replaces each match with
"[redacted: <rule id>]".
"""
import importlib.util
import math
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))


def hooks_dir():
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        candidate = os.path.join(root, "hooks")
        if os.path.isfile(os.path.join(candidate, "gitleaks_rules.py")):
            return candidate
    return HERE


# Extra shapes for public services and standard formats that gitleaks's
# default rules miss or match only next to a keyword. Each entry is
# (rule id, compiled regex, lowercase keywords that must appear in the text).
# When a regex has a capture group, only the first group that matched is
# redacted, so the rest of the match stays readable.
EXTRA_SHAPES = [
    # The password in a URL's userinfo, e.g. postgresql://user:<password>@host
    # or redis://:<password>@host. The scheme, user and host stay visible.
    ("connection-string-password", re.compile(
        r"\b[A-Za-z][A-Za-z0-9+.-]{1,30}://[^\s/:@'\"<>]*:([^\s/@'\"<>]{3,})@[^\s/@'\"<>]"), ("://",)),
    ("1password-service-account", re.compile(r"ops_[A-Za-z0-9_-]{20,}"), ("ops_",)),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), ("github_pat_",)),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), ("sk-ant-",)),
    ("private-key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL),
     ("private key-----",)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), ("eyj",)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), ("akia", "asia")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), ("xox",)),
]


def _load_gitleaks():
    path = os.path.join(hooks_dir(), "gitleaks_rules.py")
    spec = importlib.util.spec_from_file_location("gitleaks_redact_rules", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_GL = _load_gitleaks()
VERSION = _GL.VERSION
UNCOMPILED = _GL.UNCOMPILED


# gitleaks rules open with a lazy "[\w.-]{0,50}?" run so a match can start
# inside an identifier. Python's re engine makes that lead slow, so it is
# stripped from the regex and the match start is walked back by hand instead.
_LEAD = re.compile(r"^(\(\?i\))?((?:\[\\w\.-\]\{0,50\}\?(?:\(\?i:)?)+)")
_LEAD_RUN = "[\\w.-]{0,50}?"


def strip_lead(source):
    m = _LEAD.match(source)
    if not m:
        return source, 0
    lead = m.group(2)
    return (m.group(1) or "") + lead.replace(_LEAD_RUN, "") + source[m.end():], 50 * lead.count(_LEAD_RUN)


class Rule:
    __slots__ = ("id", "source", "keywords", "entropy", "group", "allowlists", "extra", "lead", "_rx")

    def __init__(self, rid, source, keywords, entropy=0.0, group=0, allowlists=(), extra=False):
        self.id, self.source, self.keywords = rid, source, keywords
        self.entropy, self.group, self.allowlists, self.extra = entropy, group, allowlists, extra
        self._rx = source if isinstance(source, re.Pattern) else None
        self.lead = 0

    @property
    def regex(self):
        if self._rx is None:
            source, self.lead = strip_lead(self.source)
            self._rx = re.compile(source)
        return self._rx


RULES = [Rule(*r) for r in _GL.RULES] + [Rule(rid, src, kw, extra=True) for rid, src, kw in EXTRA_SHAPES]
_GLOBAL_STOPWORDS = _GL.GLOBAL_ALLOWLIST["stopwords"]
_GLOBAL = []


def _global_regexes():
    if not _GLOBAL:
        _GLOBAL.extend(re.compile(x) for x in _GL.GLOBAL_ALLOWLIST["regexes"])
    return _GLOBAL


def _is_lead(ch):
    return ch.isalnum() or ch in "_.-"


def _match_start(text, start, floor, cap):
    at = start
    while at > floor and start - at < cap and _is_lead(text[at - 1]):
        at -= 1
    return at


def shannon(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def _allowed_by(a, secret, match, line):
    target = {"match": match, "line": line}.get(a["target"], secret)
    checks = []
    if a["regexes"]:
        checks.append(any(re.search(x, target) for x in a["regexes"]))
    if a["stopwords"]:
        low = secret.lower()
        checks.append(any(w in low for w in a["stopwords"]))
    if a["paths"]:
        checks.append(False)
    if not checks:
        return False
    return all(checks) if a["condition"] == "AND" else any(checks)


def _line_at(text, start, end):
    return text[text.rfind("\n", 0, start) + 1:(text.find("\n", end) + 1 or len(text) + 1) - 1]


def _finds(rule, text):
    regex, floor = rule.regex, 0
    for m in regex.finditer(text):
        start = _match_start(text, m.start(), floor, rule.lead) if rule.lead else m.start()
        floor = m.end()
        span = (start, m.end())
        if rule.group:
            span = m.span(rule.group)
        elif m.re.groups:
            span = next((m.span(g) for g in range(1, m.re.groups + 1) if m.group(g)), span)
        if span[0] == span[1]:
            continue
        secret = text[span[0]:span[1]]
        if not rule.extra:
            if rule.entropy and shannon(secret) <= rule.entropy:
                continue
            if rule.id.startswith("generic") and not any(ch.isdigit() for ch in secret):
                continue
            if any(x.search(secret) for x in _global_regexes()):
                continue
            low = secret.lower()
            if any(w in low for w in _GLOBAL_STOPWORDS):
                continue
            line = _line_at(text, start, m.end())
            if any(_allowed_by(a, secret, text[start:m.end()], line) for a in rule.allowlists):
                continue
        yield span


def scan(text):
    """Return non-overlapping (start, end, rule id) spans of secrets in text."""
    if not text:
        return []
    low = text.lower()
    hits = []
    for rule in RULES:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        hits += [(s, e, rule.id) for s, e in _finds(rule, text)]
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0]), h[2].startswith("generic")))
    out = []
    for s, e, rid in hits:
        if out and s < out[-1][1]:
            if e > out[-1][1]:
                out[-1] = (out[-1][0], e, out[-1][2])
            continue
        out.append((s, e, rid))
    return out


def redact_text(text):
    """Return (redacted text, list of rule ids that matched)."""
    spans = scan(text)
    if not spans:
        return text, []
    parts, at = [], 0
    for s, e, rid in spans:
        parts += [text[at:s], f"[redacted: {rid}]"]
        at = e
    parts.append(text[at:])
    return "".join(parts), [rid for _, _, rid in spans]


def redact(value):
    if isinstance(value, str):
        return redact_text(value)[0]
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
