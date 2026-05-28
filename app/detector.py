import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class SecretPattern:
    type: str
    severity: str
    regex: Pattern[str]


SECRET_PATTERNS = [
    SecretPattern(
        type="AWS Access Key ID",
        severity="high",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    SecretPattern(
        type="AWS Secret Access Key",
        severity="critical",
        regex=re.compile(
            r"(?i)\bAWS(?:_|\s|-)*SECRET(?:_|\s|-)*ACCESS(?:_|\s|-)*KEY\b"
            r"\s*[:=]\s*['\"]?"
            r"(?P<secret>[A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    SecretPattern(
        type="OpenAI API Key",
        severity="critical",
        regex=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretPattern(
        type="GitHub Token",
        severity="critical",
        regex=re.compile(
            r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b"
        ),
    ),
    SecretPattern(
        type="JWT Token",
        severity="high",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ),
    SecretPattern(
        type="Generic Secret Assignment",
        severity="medium",
        regex=re.compile(
            r"(?i)\b[A-Z0-9_]*(?:PASSWORD|PASSWD|API_KEY|SECRET)[A-Z0-9_]*\b"
            r"\s*[:=]\s*['\"]?(?P<secret>[^\s'\";,]+)['\"]?"
        ),
    ),
]

SEVERITY_SCORES = {
    "low": 15,
    "medium": 35,
    "high": 70,
    "critical": 90,
}


def detect_secrets(content: str) -> list[dict]:
    detections = []

    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(content):
            start, end = _secret_span(match)
            if _overlaps_existing(detections, start, end):
                continue

            value = content[start:end]
            detections.append(
                {
                    "type": pattern.type,
                    "severity": pattern.severity,
                    "start": start,
                    "end": end,
                    "masked_value": _mask_value(value),
                }
            )

    return sorted(detections, key=lambda item: item["start"])


def mask_secrets(content: str, detections: list[dict]) -> str:
    sanitized = content

    for detection in sorted(detections, key=lambda item: item["start"], reverse=True):
        sanitized = (
            sanitized[: detection["start"]]
            + "[REDACTED]"
            + sanitized[detection["end"] :]
        )

    return sanitized


def scan_content(input_type: str, content: str, filename: str | None = None) -> dict:
    detections = detect_secrets(content)

    return {
        "input_type": input_type,
        "filename": filename,
        "detected_count": len(detections),
        "risk_score": calculate_risk_score(detections),
        "detected_types": sorted({detection["type"] for detection in detections}),
        "detections": detections,
        "sanitized_output": mask_secrets(content, detections),
    }


def placeholder_scan(input_type: str, content: str, filename: str | None = None) -> dict:
    return scan_content(input_type=input_type, content=content, filename=filename)


def calculate_risk_score(detections: list[dict]) -> int:
    if not detections:
        return 0

    score = sum(SEVERITY_SCORES[detection["severity"]] for detection in detections)
    return min(score, 100)


def _secret_span(match: re.Match) -> tuple[int, int]:
    if "secret" in match.groupdict() and match.group("secret") is not None:
        return match.span("secret")

    return match.span()


def _overlaps_existing(detections: list[dict], start: int, end: int) -> bool:
    return any(start < detection["end"] and end > detection["start"] for detection in detections)


def _mask_value(value: str) -> str:
    return "[REDACTED]" if value else ""
