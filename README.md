# AI Secret Leakage Detector

[![Tests](https://github.com/omer-shen-tzur/secret-leakage-detector/actions/workflows/tests.yml/badge.svg)](https://github.com/omer-shen-tzur/secret-leakage-detector/actions/workflows/tests.yml)

AI Secret Leakage Detector is a simple FastAPI MVP that scans pasted prompts and uploaded text-based files before they are sent to an AI model.

The project is designed as a practical AI security middleware demo. It helps identify likely secrets, masks them, and returns a sanitized version of the input with a basic risk score.

## Problem Statement

AI tools are often used with prompts, source code, configuration files, logs, and environment snippets. These inputs can accidentally contain API keys, passwords, cloud credentials, tokens, or other sensitive values.

This MVP demonstrates a lightweight pre-processing layer that can sit before an AI model and reduce the chance of leaking secrets into an external system.

## Features

- Scan pasted text
- Scan uploaded text-based files
- Detect common secret patterns with regular expressions
- Mask detected secret values with `[REDACTED]`
- Return sanitized output
- Show detected secret type, severity, and masked value
- Generate a simple risk score
- Reject unsupported file types
- Reject binary or unreadable files
- Store only scan metadata in SQLite

## Supported File Types

The file scanner treats the following extensions as text-based files:

```text
.txt
.env
.json
.md
.py
.js
.ts
.yaml
.yml
.ini
.cfg
```

Binary parsing is intentionally not supported in this MVP.

## Supported Secret Types

The current regex detector supports:

- AWS Access Key ID
- AWS Secret Access Key
- OpenAI API Key
- GitHub token
- JWT token
- Generic secret assignments, such as:
  - `password=...`
  - `DB_PASSWORD=...`
  - `API_KEY=...`
  - `SECRET=...`

## Architecture Flow

```text
Browser UI
  |
  | paste text or upload file
  v
FastAPI routes
  |
  | validate input
  v
File/text utilities
  |
  | decode text safely
  v
Regex detector
  |
  | detect, score, mask
  v
JSON response
  |
  | render result in browser
  v
Sanitized output + risk score
```

SQLite is used only for scan metadata. Raw input and sanitized output should not be stored.

## Project Structure

```text
app/
  main.py            FastAPI routes and app setup
  detector.py        Regex-based secret detection and masking
  file_utils.py      File extension validation and text decoding
  models.py          SQLite metadata model
  schemas.py         API response schemas
  database.py        SQLite initialization
  templates/         HTML frontend
  static/            CSS

tests/
  conftest.py         Shared pytest fixtures
  secret_samples.py   Runtime-built fake secret values for tests
  test_api.py         API route validation tests
  test_detector.py    Detector tests
  test_file_utils.py  File extension/decoding tests
```

## Run Locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the app:

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/
```

## Testing

Install test dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the test suite:

```bash
python -m pytest
```

Run with a coverage report:

```bash
python -m pytest --cov=app --cov-report=term-missing
```

What's covered:

- `app/detector.py`: every secret pattern (AWS access key ID, AWS secret access key, OpenAI key, GitHub token, JWT, generic password/API key/secret assignments), including near-miss/false-positive cases, case-insensitivity, quoted vs. unquoted values, overlapping matches, detection ordering, masking, and risk score capping.
- `app/file_utils.py`: allowed/blocked extensions (including uppercase), non-UTF-8 and binary content, empty and whitespace-only files.
- `app/main.py`: the `/scan/text` and `/scan/file` routes, via FastAPI's `TestClient`.

Test secrets are never written as real-looking literals. Patterns like AWS access keys or OpenAI keys are assembled at runtime from inert parts (e.g. `"AKIA" + "X" * 16`) so they satisfy the detector's regexes without tripping GitHub push protection or other secret scanners.

CI (`.github/workflows/tests.yml`) runs on every push and pull request across a matrix of:

- OS: `ubuntu-latest`, `ubuntu-24.04-arm` (ARM64)
- Python: `3.11`, `3.12`

Each run produces a coverage summary and a JUnit XML report, uploaded as a build artifact.

## Run With Docker

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8000/
```

## Run On Local Network

To test from another device on the same Wi-Fi network, run the app on all interfaces:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Find your laptop's local IPv4 address:

```powershell
ipconfig
```

Look for the Wi-Fi adapter IPv4 address, for example:

```text
192.168.1.111
```

Then open this from another device on the same Wi-Fi:

```text
http://192.168.1.111:8000/
```

If Windows Firewall blocks access, allow inbound TCP port `8000` on Private networks:

```powershell
New-NetFirewallRule `
  -DisplayName "AI Secret Leakage Detector Local Demo TCP 8000" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 8000 `
  -Profile Private
```

## Example Inputs

Text prompt example:

```text
Please review this config before deployment:
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890
DB_PASSWORD=my-local-password
```

Python file example:

```python
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
password = "local-dev-password"
```

JavaScript file example:

```js
const password = "client-secret";
const token = "ghp_abcdefghijklmnopqrstuvwxyz123456";
```

Environment file example:

```text
AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
SECRET=demo-secret
```

## Database Policy

The SQLite database is intended to store scan metadata only:

- `input_type`
- `detected_count`
- `risk_score`
- `detected_types`
- `created_at`

The app should not store raw input or sanitized output.

## Limitations

- Regex-based detection can produce false positives and false negatives.
- Only UTF-8 readable text files are supported.
- No PDF, Word, image, archive, or OCR parsing.
- No authentication or multi-user support.
- No browser extension or IDE integration.
- No external AI model integration.
- Risk scoring is intentionally simple.
- This is a local MVP, not a production security gateway.

## Future Improvements

- Add configurable detection rules
- Add more provider-specific secret patterns
- Add severity explanations and remediation tips
- Add optional scan history view for metadata only
- Add exportable reports
- Add pre-commit hook integration
- Add IDE or browser extension integration
- Add policy controls for blocking high-risk prompts
- Add production hardening if deployed beyond a local demo
