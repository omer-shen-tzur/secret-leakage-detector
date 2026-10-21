import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_home_page_loads():
    response = client.get("/")

    assert response.status_code == 200
    assert "AI Secret Leakage Detector" in response.text


def test_scan_text_returns_detector_result():
    response = client.post(
        "/scan/text",
        data={"text": "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["detected_count"] == 1
    assert body["risk_score"] == 90
    assert body["detected_types"] == ["OpenAI API Key"]
    assert body["sanitized_output"] == "OPENAI_API_KEY=[REDACTED]"
    assert body["detections"][0]["severity"] == "critical"


def test_scan_text_rejects_empty_input():
    response = client.post("/scan/text", data={"text": "   "})

    assert response.status_code == 400
    assert response.json()["detail"] == "Input text cannot be empty."


def test_scan_file_accepts_supported_text_file():
    response = client.post(
        "/scan/file",
        files={
            "file": (
                "sample.env",
                b"DB_PASSWORD=db-password",
                "text/plain",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "sample.env"
    assert body["detected_count"] == 1
    assert body["sanitized_output"] == "DB_PASSWORD=[REDACTED]"


def test_scan_file_accepts_python_file():
    response = client.post(
        "/scan/file",
        files={
            "file": (
                "settings.py",
                b'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"',
                "text/x-python",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "settings.py"
    assert body["detected_types"] == ["OpenAI API Key"]
    assert body["sanitized_output"] == 'OPENAI_API_KEY = "[REDACTED]"'


def test_scan_file_accepts_javascript_file():
    response = client.post(
        "/scan/file",
        files={
            "file": (
                "config.js",
                b'const password = "client-secret";',
                "application/javascript",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "config.js"
    assert body["detected_types"] == ["Generic Secret Assignment"]
    assert body["sanitized_output"] == 'const password = "[REDACTED]";'


def test_scan_file_accepts_yaml_file():
    response = client.post(
        "/scan/file",
        files={
            "file": (
                "secrets.yaml",
                b"SECRET: yaml-secret-value",
                "application/yaml",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "secrets.yaml"
    assert body["detected_types"] == ["Generic Secret Assignment"]
    assert body["sanitized_output"] == "SECRET: [REDACTED]"


def test_scan_file_rejects_unsupported_type():
    response = client.post(
        "/scan/file",
        files={"file": ("sample.csv", b"password=value", "text/csv")},
    )

    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]
    assert ".py" in response.json()["detail"]
    assert ".js" in response.json()["detail"]


def test_scan_file_rejects_binary_content():
    response = client.post(
        "/scan/file",
        files={"file": ("sample.txt", b"\x00\x01\x02", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Binary files are not supported."


def test_scan_file_rejects_non_utf8_content():
    response = client.post(
        "/scan/file",
        files={"file": ("sample.txt", b"caf\xe9 not valid utf-8", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "File must be readable as UTF-8 text."


@pytest.mark.parametrize(
    "filename",
    [
        pytest.param("sample.ENV", id="uppercase-env-extension"),
        pytest.param("CONFIG.PY", id="uppercase-py-extension"),
    ],
)
def test_scan_file_accepts_uppercase_extensions(filename):
    response = client.post(
        "/scan/file",
        files={"file": (filename, b"password=supersecretvalue", "text/plain")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == filename
    assert body["detected_types"] == ["Generic Secret Assignment"]


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"", id="empty-file"),
        pytest.param(b"   \n\t  ", id="whitespace-only-file"),
    ],
)
def test_scan_file_rejects_empty_or_whitespace_only_content(content):
    response = client.post(
        "/scan/file",
        files={"file": ("sample.txt", content, "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded file cannot be empty."
