import importlib.util
import os

import pytest

HOOKS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HOOKS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def _plugin_env(monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", os.path.dirname(HOOKS))
    monkeypatch.delenv("GITLEAKS_REDACT_LOG", raising=False)


@pytest.fixture
def hook():
    return _load("output_redact_under_test", "output_redact.py")


@pytest.fixture(scope="session")
def shapes():
    return _load("secret_shapes_under_test", "secret_shapes.py")


# Obviously fake secrets, built by concatenation so no literal in this
# repository looks like a real credential to a scanner.
FAKE_AWS = "AKIA" + "QWERTYUI23456789"
FAKE_GITHUB = "ghp" + "_" + "0123456789abcdefABCDEF0123456789abcd"
FAKE_SLACK = "xox" + "b-" + "000000000000-fakefakefake"
