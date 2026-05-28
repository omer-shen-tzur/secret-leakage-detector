# Project Summary

## What Was Built

AI Secret Leakage Detector is a local FastAPI MVP that scans pasted text and uploaded text-based files for likely secrets before they are sent to an AI model.

It provides a simple browser UI, regex-based detection, masking, sanitized output, and a risk score. The project is intentionally small and focused on demonstrating an AI security middleware concept.

## How It Works

1. A user pastes text or uploads a supported text file.
2. FastAPI validates the request.
3. Uploaded files are checked by extension and decoded as UTF-8 text.
4. The detector searches the content with regular expressions.
5. Each detection includes type, severity, start index, end index, and masked value.
6. Detected values are replaced with `[REDACTED]`.
7. The app returns detections, risk score, and sanitized output to the frontend.

The SQLite model is reserved for scan metadata only. Raw input and sanitized output are not intended to be stored.

## Current MVP Status

The MVP currently supports:

- Pasted text scanning
- Text-based file upload scanning
- Secret masking
- Risk scoring
- Clean error handling for empty input, unsupported file types, binary files, and unreadable files
- Local browser demo
- Local network demo over Wi-Fi
- Docker-based startup
- Focused API and detector tests

Supported file types:

```text
.txt, .env, .json, .md, .py, .js, .ts, .yaml, .yml, .ini, .cfg
```

Supported secret categories:

- AWS Access Key ID
- AWS Secret Access Key
- OpenAI API Key
- GitHub token
- JWT token
- Generic password/API key/secret assignments

## Roadmap Options

Good next steps for a portfolio version:

- Add a small scan history page for metadata only
- Add configurable regex rules
- Add more cloud and SaaS token patterns
- Add severity descriptions
- Add remediation suggestions
- Add a pre-commit hook mode
- Add CLI support for scanning local files
- Add optional block/allow policy decisions
- Improve production deployment guidance

The next product step should still preserve the core security principle: do not store raw secrets.
