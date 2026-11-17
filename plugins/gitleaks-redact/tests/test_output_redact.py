import io
import json

import pytest

from conftest import FAKE_AWS, FAKE_GITHUB, FAKE_SLACK


def run(hook, payload):
    out, err = io.StringIO(), io.StringIO()
    assert hook.main(io.StringIO(json.dumps(payload)), out, err) == 0
    text = out.getvalue()
    return (json.loads(text) if text else None), err.getvalue()


def replacement(result):
    assert result is not None
    spec = result["hookSpecificOutput"]
    assert spec["hookEventName"] == "PostToolUse"
    return spec["updatedToolOutput"]


TOOL_SHAPES = {
    "Bash": lambda s: {"stdout": f"key={s}\n", "stderr": "", "interrupted": False, "isImage": False},
    "Read": lambda s: {"type": "text", "file": {"filePath": "/tmp/x.env", "content": f"AWS_KEY={s}\n",
                                                "numLines": 1, "startLine": 1, "totalLines": 1}},
    "Grep": lambda s: {"mode": "content", "numFiles": 1, "filenames": ["x.env"],
                       "content": f"x.env:1:{s}", "numLines": 1},
    "WebFetch": lambda s: {"bytes": 100, "code": 200, "codeText": "OK", "result": f"token {s}",
                           "durationMs": 5, "url": "https://example.com/"},
    "mcp__example__read": lambda s: [{"type": "text", "text": f"secret: {s}"}],
}


@pytest.mark.parametrize("tool", sorted(TOOL_SHAPES))
@pytest.mark.parametrize("secret", [FAKE_AWS, FAKE_GITHUB, FAKE_SLACK])
def test_each_tool_shape_is_redacted(hook, tool, secret):
    original = TOOL_SHAPES[tool](secret)
    result, _ = run(hook, {"tool_name": tool, "tool_response": original})
    value = replacement(result)
    assert hook.same_shape(original, value)
    dumped = json.dumps(value)
    assert secret not in dumped
    assert "[redacted: " in dumped


def test_mcp_string_output_is_redacted(hook):
    result, _ = run(hook, {"tool_name": "mcp__example__get", "tool_response": f"value {FAKE_AWS}"})
    value = replacement(result)
    assert isinstance(value, str) and FAKE_AWS not in value and "[redacted: " in value


@pytest.mark.parametrize("tool", sorted(TOOL_SHAPES))
def test_no_match_passes_output_through(hook, tool):
    result, err = run(hook, {"tool_name": tool, "tool_response": TOOL_SHAPES[tool]("nothing secret here")})
    assert result is None
    assert err == ""


def test_other_tools_are_ignored(hook):
    result, _ = run(hook, {"tool_name": "Write", "tool_response": {"content": FAKE_AWS}})
    assert result is None


def test_image_output_is_skipped(hook):
    result, _ = run(hook, {"tool_name": "Read", "tool_response": {"type": "image", "file": {"base64": FAKE_AWS}}})
    assert result is None


def test_bad_stdin_prints_nothing(hook):
    out, err = io.StringIO(), io.StringIO()
    assert hook.main(io.StringIO("not json"), out, err) == 0
    assert out.getvalue() == ""


class ShapeChangingShapes:
    """Pretends redaction turned a string into a list."""

    @staticmethod
    def redact_text(text):
        return ([text], ["fake-rule"]) if "secret" in text else (text, [])


def test_wrong_shape_is_not_returned(hook, monkeypatch):
    original = TOOL_SHAPES["Bash"]("secret " + FAKE_AWS)
    value, rules, status = hook.updated_output({"tool_name": "Bash", "tool_response": original},
                                               shapes=ShapeChangingShapes)
    assert status == "wrong-shape"
    assert hook.same_shape(original, value)
    assert value["stdout"] == hook.WITHHELD

    monkeypatch.setattr(hook, "_shapes", lambda: ShapeChangingShapes)
    result, err = run(hook, {"tool_name": "Bash", "tool_response": original})
    returned = replacement(result)
    assert returned["stdout"] == hook.WITHHELD
    assert FAKE_AWS not in json.dumps(returned)
    assert "changed shape" in err


def test_crash_fails_closed(hook, monkeypatch):
    def boom():
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(hook, "_shapes", boom)
    original = TOOL_SHAPES["Read"](FAKE_AWS)
    result, err = run(hook, {"tool_name": "Read", "tool_response": original})
    value = replacement(result)
    assert hook.same_shape(original, value)
    assert value["file"]["content"] == hook.WITHHELD
    assert value["file"]["filePath"] == hook.WITHHELD
    assert value["file"]["numLines"] == 1
    assert FAKE_AWS not in json.dumps(value)
    assert "withheld" in err


def test_log_is_off_by_default(hook, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    run(hook, {"tool_name": "Bash", "tool_response": TOOL_SHAPES["Bash"](FAKE_AWS)})
    assert list(tmp_path.iterdir()) == []


def test_log_holds_rule_ids_not_matched_text(hook, tmp_path, monkeypatch):
    path = tmp_path / "redactions.jsonl"
    monkeypatch.setenv("GITLEAKS_REDACT_LOG", str(path))
    run(hook, {"tool_name": "Bash", "tool_response": TOOL_SHAPES["Bash"](FAKE_AWS), "session_id": "s1"})
    text = path.read_text()
    assert FAKE_AWS not in text
    rec = json.loads(text)
    assert rec["tool"] == "Bash" and rec["status"] == "redacted" and rec["rules"]


def test_shapes_pin_gitleaks_version(shapes):
    assert shapes.VERSION == "v8.30.1"


def context(result):
    assert result is not None
    return result["hookSpecificOutput"]["additionalContext"]


def test_redaction_tells_the_model(hook):
    result, _ = run(hook, {"tool_name": "Bash", "tool_response": TOOL_SHAPES["Bash"](FAKE_AWS)})
    text = context(result)
    assert "replaced 1 secret value(s) in this Bash output" in text
    assert "aws-access-key" in text
    assert "Do not try to recover" in text
    assert "Do not write the redacted text back to a file" in text
    assert "Tell the user which tool call exposed a secret" in text
    assert FAKE_AWS not in text


def test_withheld_output_tells_the_model(hook, monkeypatch):
    def boom():
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(hook, "_shapes", boom)
    result, _ = run(hook, {"tool_name": "Read", "tool_response": TOOL_SHAPES["Read"](FAKE_AWS)})
    text = context(result)
    assert "withheld this entire Read output" in text
    assert "status: failed" in text and "hook-error" in text


def test_clean_output_adds_no_context(hook):
    result, _ = run(hook, {"tool_name": "Bash", "tool_response": TOOL_SHAPES["Bash"]("nothing here")})
    assert result is None


FAKE_PW = "Zr8Kq2" + "Lm9Vx4Tn7Wp3Bd"


@pytest.mark.parametrize("url", [
    f"postgresql://aptible:{FAKE_PW}@db-1.example.internal:5432/db",
    f"DATABASE_URL=postgres://app_user:{FAKE_PW}@10.0.0.5/app",
    f"REDIS_URL=redis://:{FAKE_PW}@redis.example.internal:6379",
    f"amqps://guest:{FAKE_PW}@mq.example.internal/vhost",
    f'{{"url": "mysql://root:{FAKE_PW}@db:3306/x"}}',
])
def test_connection_string_password_is_redacted(shapes, url):
    text, rules = shapes.redact_text(url)
    assert FAKE_PW not in text
    assert "connection-string-password" in rules
    assert "@" in text and "://" in text


def test_connection_string_keeps_user_and_host(shapes):
    text, _ = shapes.redact_text(f"postgresql://aptible:{FAKE_PW}@db-1.example.internal:5432/db")
    assert text == "postgresql://aptible:[redacted: connection-string-password]@db-1.example.internal:5432/db"


@pytest.mark.parametrize("plain", [
    "https://example.com/path?a=1",
    "https://user@example.com/repo.git",
    "ssh://git@github.com:22/org/repo.git",
    "see http://example.com:8080/ for details",
])
def test_urls_without_a_password_pass(shapes, plain):
    text, rules = shapes.redact_text(plain)
    assert text == plain and not rules
