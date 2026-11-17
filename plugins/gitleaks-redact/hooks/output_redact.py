#!/usr/bin/env python3
"""PostToolUse hook: redact secrets from tool output before the model sees it.

Reads the hook payload on stdin. When the output of a Bash, Read, Grep,
WebFetch or MCP tool contains a secret, prints a hookSpecificOutput whose
updatedToolOutput has the same shape as the original, with each match
replaced by "[redacted: <rule id>]". Needs Claude Code 2.1.121 or later.

If redaction would change the output's shape, or the hook crashes, every
string in the output is replaced with a notice instead (fail closed).

Optional log: set GITLEAKS_REDACT_LOG to a file path to append one JSON line
per redaction. The log holds rule ids, the tool name, a status and the
session id. It never holds matched text.
"""
import importlib.util
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = re.compile(r"Bash|Read|Grep|WebFetch|mcp__.+")
LOG_ENV = "GITLEAKS_REDACT_LOG"
LOG_MAX_BYTES = 5_000_000
WITHHELD = "[withheld: the gitleaks-redact hook failed, so this output was not shown]"


def hooks_dir():
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        candidate = os.path.join(root, "hooks")
        if os.path.isfile(os.path.join(candidate, "secret_shapes.py")):
            return candidate
    return HERE


def _shapes():
    path = os.path.join(hooks_dir(), "secret_shapes.py")
    spec = importlib.util.spec_from_file_location("gitleaks_redact_shapes", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def same_shape(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_shape(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_shape(x, y) for x, y in zip(a, b))
    return True


def skipped(tool, response):
    """Image and other non-text output is left alone."""
    if not isinstance(response, dict):
        return False
    if tool == "Bash" and response.get("isImage"):
        return True
    return tool == "Read" and response.get("type") not in (None, "text")


def withhold(value):
    if isinstance(value, str):
        return WITHHELD
    if isinstance(value, dict):
        return {k: withhold(v) for k, v in value.items()}
    if isinstance(value, list):
        return [withhold(v) for v in value]
    return value


def _walk(shapes, value, rules):
    if isinstance(value, str):
        text, hit = shapes.redact_text(value)
        rules += hit
        return text
    if isinstance(value, dict):
        return {k: _walk(shapes, v, rules) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(shapes, v, rules) for v in value]
    return value


def log(payload, tool, rules, status):
    path = os.environ.get(LOG_ENV)
    if not path:
        return
    path = os.path.expanduser(path)
    session = payload.get("session_id")
    rec = {"ts": int(time.time()), "tool": tool if isinstance(tool, str) else None,
           "rules": sorted(set(rules)), "status": status,
           "session_id": session if isinstance(session, str) else None}
    try:
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
            return
        fd = os.open(path,os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(rec) + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass


def updated_output(payload, shapes=None):
    """Return (replacement output or None, rule ids, status)."""
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not TOOLS.fullmatch(tool) or "tool_response" not in payload:
        return None, [], "skip"
    response = payload["tool_response"]
    if skipped(tool, response):
        return None, [], "skip"
    shapes = shapes or _shapes()
    rules = []
    redacted = _walk(shapes, response, rules)
    if not rules:
        return None, [], "clean"
    if not same_shape(response, redacted):
        return withhold(response), rules, "wrong-shape"
    return redacted, rules, "redacted"


def main(stdin=None, stdout=None, stderr=None):
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    try:
        payload = json.loads(stdin.read())
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0
    try:
        value, rules, status = updated_output(payload)
    except Exception as e:
        stderr.write(f"gitleaks-redact: {type(e).__name__}; the output was withheld\n")
        if "tool_response" not in payload:
            return 0
        value, rules, status = withhold(payload["tool_response"]), ["hook-error"], "failed"
    if rules:
        log(payload, payload.get("tool_name"), rules, status)
    if status == "wrong-shape":
        stderr.write("gitleaks-redact: the redacted output changed shape, so the output was withheld\n")
    if value is None:
        return 0
    stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": value}}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
