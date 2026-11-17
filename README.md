# claude-code-plugins

A Claude Code plugin marketplace. It has one plugin so far.

## gitleaks-redact

gitleaks-redact is a PostToolUse hook. It scans the output of the Bash, Read, Grep, WebFetch and MCP tools for secrets, and replaces each one with `[redacted: <rule id>]` before the model sees it. For example, an AWS access key in a `.env` file that Claude reads becomes `[redacted: aws-access-key]`.

It uses the default rules from [gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1, converted to Python, plus a few extra shapes for common services such as GitHub, Slack, AWS, Anthropic, 1Password, JWTs and PEM private keys. It also redacts the password in connection strings such as `postgresql://user:<password>@host` and `redis://:<password>@host`, leaving the scheme, user and host readable. It leaves obvious placeholders alone: a password equal to the user name, `password`, `changeme`, `****`, or template syntax such as `${DB_PASSWORD}` and `{password}`.

The hook returns the redacted output in the same shape as the tool's original output. If redaction would change that shape, or the hook itself crashes while scanning, it withholds the output instead: every string in it is replaced with a notice. Two failures still let the original output through: input the hook cannot parse as JSON, and a scan that runs past the hook's 30-second timeout.

Each time it redacts or withholds output, the hook also gives the model a short note (`additionalContext`). The note names the rules that matched and tells the model three things:

- Do not try to recover the values with other commands, encodings or partial reads.
- Do not write the redacted text back to a file, since the placeholders would replace the real values.
- Tell the user which tool call exposed a secret, so they can decide whether to rotate it.

### Install

In Claude Code:

```
/plugin marketplace add Lingnik/claude-code-plugins
/plugin install gitleaks-redact@lingnik
```

### Requirements

- Python 3 on your `PATH` as `python3`. The hook uses only the standard library.
- Claude Code 2.1.121 or later. Earlier versions ignore `updatedToolOutput`, so the hook has no effect there.

### Optional log

The hook writes no log by default. To get one, set `GITLEAKS_REDACT_LOG` to a file path. Each redaction appends one JSON line with the time, the tool name, the rule ids that matched, a status and the session id. The log never contains the matched text. It stops growing at about 5 MB.

### Limits

- It changes only what the model sees. The tool still ran and still read the secret. OpenTelemetry spans keep the original output. In our test, the session transcript stored the redacted text.
- It covers only the Bash, Read, Grep, WebFetch and MCP tools. Output from any other tool passes through untouched, and so do images.
- Regular expressions miss things. A secret in an unusual format, split across lines or encoded will get through. Treat this as defense in depth, not a guarantee, and keep secrets out of places Claude can read.
- It can also redact things that are not secrets, such as long random-looking strings next to words like `key` or `token`, or the text between `:` and `@` in an unusual URL such as `s3://bucket:prefix@x`.
- Connection-string passwords that contain `?`, `#`, a quote or whitespace, or that run past 256 characters, are not redacted.

### Tests

```
python3 -m pytest plugins/gitleaks-redact/tests
```

## License

MIT. See `LICENSE`. The gitleaks rules are also MIT-licensed; see `THIRD_PARTY_NOTICES`.
