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
