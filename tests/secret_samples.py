"""Builders for fake secret-shaped strings used across the test suite.

Every value is assembled at runtime from inert parts (e.g. "AKIA" + "X" * 16)
instead of being written as a literal lookalike. This keeps the strings
structurally valid for the detector's regexes while staying low-entropy and
obviously fake, so they are not mistaken for real credentials by GitHub push
protection or other secret scanners.
"""


def fake_aws_access_key_id() -> str:
    return "AKIA" + "X" * 16


def fake_aws_session_key_id() -> str:
    return "ASIA" + "Y" * 16


def fake_aws_secret_access_key() -> str:
    body = ("fake" + "0123456789") * 4
    return body[:40]


def fake_openai_key() -> str:
    return "sk-" + "proj-" + "X" * 20


def fake_openai_key_legacy() -> str:
    return "sk-" + "X" * 20


def fake_github_token(prefix: str = "ghp") -> str:
    return f"{prefix}_" + "X" * 24


def fake_github_pat() -> str:
    return "github_pat_" + "X" * 24


def fake_jwt() -> str:
    header = "eyJ" + "A" * 10
    payload = "B" * 20
    signature = "C" * 20
    return f"{header}.{payload}.{signature}"
