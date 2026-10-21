import pytest

from app.detector import (
    calculate_risk_score,
    detect_secrets,
    mask_secrets,
    placeholder_scan,
)
from secret_samples import (
    fake_aws_access_key_id,
    fake_aws_secret_access_key,
    fake_github_pat,
    fake_github_token,
    fake_jwt,
    fake_openai_key,
    fake_openai_key_legacy,
)


def test_detects_required_secret_types(fake_secrets):
    content = "\n".join(
        [
            f"aws_key = {fake_secrets['AWS Access Key ID']}",
            f"AWS_SECRET_ACCESS_KEY={fake_secrets['AWS Secret Access Key']}",
            f"OPENAI_API_KEY={fake_secrets['OpenAI API Key']}",
            f"GITHUB_TOKEN={fake_secrets['GitHub Token']}",
            f"jwt={fake_secrets['JWT Token']}",
            "password=supersecretvalue",
            "DB_PASSWORD=supersecretvalue",
            "API_KEY=supersecretvalue",
            "SECRET=supersecretvalue",
        ]
    )

    detections = detect_secrets(content)
    detected_types = [detection["type"] for detection in detections]

    assert "AWS Access Key ID" in detected_types
    assert "AWS Secret Access Key" in detected_types
    assert "OpenAI API Key" in detected_types
    assert "GitHub Token" in detected_types
    assert "JWT Token" in detected_types
    assert detected_types.count("Generic Secret Assignment") == 4


def test_detection_returns_required_fields():
    secret = fake_openai_key()
    content = f"OPENAI_API_KEY={secret}"

    detection = detect_secrets(content)[0]

    assert detection == {
        "type": "OpenAI API Key",
        "severity": "critical",
        "start": content.index(secret),
        "end": content.index(secret) + len(secret),
        "masked_value": "[REDACTED]",
    }


def test_masks_secret_values_and_keeps_surrounding_text_readable():
    content = "before password=supersecretvalue after"
    detections = detect_secrets(content)

    sanitized = mask_secrets(content, detections)

    assert sanitized == "before password=[REDACTED] after"


def test_scan_content_returns_sanitized_output_and_score():
    secret = fake_openai_key()
    content = f"token {secret}"

    result = placeholder_scan("text", content)

    assert result["detected_count"] == 1
    assert result["risk_score"] == 90
    assert result["detected_types"] == ["OpenAI API Key"]
    assert result["sanitized_output"] == "token [REDACTED]"


def test_aws_secret_assignment_is_not_double_counted_as_generic_secret():
    content = f"AWS_SECRET_ACCESS_KEY={fake_aws_secret_access_key()}"

    detections = detect_secrets(content)

    assert len(detections) == 1
    assert detections[0]["type"] == "AWS Secret Access Key"


# ---------------------------------------------------------------------------
# Positive matches: one representative sample per pattern type.
# ---------------------------------------------------------------------------

POSITIVE_CASES = [
    pytest.param(
        "AWS Access Key ID",
        f"aws_key = {fake_aws_access_key_id()}",
        id="aws-access-key-id",
    ),
    pytest.param(
        "AWS Secret Access Key",
        f"AWS_SECRET_ACCESS_KEY={fake_aws_secret_access_key()}",
        id="aws-secret-access-key",
    ),
    pytest.param(
        "OpenAI API Key",
        f"OPENAI_API_KEY={fake_openai_key()}",
        id="openai-key-proj-style",
    ),
    pytest.param(
        "OpenAI API Key",
        f"OPENAI_API_KEY={fake_openai_key_legacy()}",
        id="openai-key-legacy-style",
    ),
    pytest.param(
        "GitHub Token",
        f"GITHUB_TOKEN={fake_github_token()}",
        id="github-token-ghp-style",
    ),
    pytest.param(
        "GitHub Token",
        f"GITHUB_TOKEN={fake_github_pat()}",
        id="github-token-pat-style",
    ),
    pytest.param("JWT Token", f"jwt={fake_jwt()}", id="jwt-token"),
    pytest.param(
        "Generic Secret Assignment",
        "password=supersecretvalue",
        id="generic-password-assignment",
    ),
]


@pytest.mark.parametrize("expected_type, content", POSITIVE_CASES)
def test_positive_pattern_matches_detect_expected_type(expected_type, content):
    detected_types = [detection["type"] for detection in detect_secrets(content)]

    assert expected_type in detected_types


# ---------------------------------------------------------------------------
# Near misses: inputs that look close to a secret but should not be
# attributed to that pattern (false-positive guardrails).
# ---------------------------------------------------------------------------

NEAR_MISS_CASES = [
    pytest.param(
        "AWS Access Key ID",
        "aws_key = akia" + "x" * 16,
        id="aws-access-key-wrong-case",
    ),
    pytest.param(
        "AWS Access Key ID",
        "aws_key = AKIA" + "X" * 15,
        id="aws-access-key-too-short",
    ),
    pytest.param(
        "AWS Secret Access Key",
        "AWS_SECRET_ACCESS_KEY=" + fake_aws_secret_access_key()[:39],
        id="aws-secret-key-too-short",
    ),
    pytest.param(
        "OpenAI API Key",
        "OPENAI_API_KEY=sk-" + "X" * 15,
        id="openai-key-too-short",
    ),
    pytest.param(
        "GitHub Token",
        "GITHUB_TOKEN=ghx_" + "X" * 24,
        id="github-token-unknown-prefix",
    ),
    pytest.param(
        "JWT Token",
        "jwt=eyJ" + "A" * 10 + "." + "B" * 20,
        id="jwt-missing-signature-segment",
    ),
    pytest.param(
        "Generic Secret Assignment",
        "PASSENGER_COUNT=5",
        id="generic-lookalike-word-not-password",
    ),
]


@pytest.mark.parametrize("pattern_type, content", NEAR_MISS_CASES)
def test_near_miss_inputs_are_not_attributed_to_pattern(pattern_type, content):
    detected_types = [detection["type"] for detection in detect_secrets(content)]

    assert pattern_type not in detected_types


# ---------------------------------------------------------------------------
# Generic assignment: case-insensitivity and quoting.
# ---------------------------------------------------------------------------

ASSIGNMENT_STYLE_CASES = [
    pytest.param("password=secretvalue", id="lowercase-unquoted"),
    pytest.param("Password=secretvalue", id="titlecase-unquoted"),
    pytest.param("PASSWORD=secretvalue", id="uppercase-unquoted"),
    pytest.param('password="secretvalue"', id="double-quoted"),
    pytest.param("password='secretvalue'", id="single-quoted"),
    pytest.param("API_KEY=secretvalue", id="api-key-keyword"),
    pytest.param("SECRET=secretvalue", id="secret-keyword"),
    pytest.param("DB_PASSWORD: secretvalue", id="colon-separator"),
]


@pytest.mark.parametrize("content", ASSIGNMENT_STYLE_CASES)
def test_generic_assignment_detected_regardless_of_case_or_quoting(content):
    detections = detect_secrets(content)

    assert len(detections) == 1
    assert detections[0]["type"] == "Generic Secret Assignment"


@pytest.mark.parametrize(
    "content, expected_sanitized",
    [
        pytest.param("password=secretvalue", "password=[REDACTED]", id="unquoted"),
        pytest.param(
            'password="secretvalue"', 'password="[REDACTED]"', id="double-quoted"
        ),
        pytest.param(
            "password='secretvalue'", "password='[REDACTED]'", id="single-quoted"
        ),
    ],
)
def test_masking_preserves_quote_characters_around_secret(content, expected_sanitized):
    detections = detect_secrets(content)

    assert mask_secrets(content, detections) == expected_sanitized


# ---------------------------------------------------------------------------
# Multiple secrets, overlapping matches, and ordering.
# ---------------------------------------------------------------------------


def test_multiple_distinct_secrets_are_all_detected_and_ordered_by_position():
    content = "\n".join(
        [
            f"token: {fake_github_token()}",
            "middle text with no secrets",
            f"aws: {fake_aws_access_key_id()}",
            f"end: {fake_openai_key()}",
        ]
    )

    detections = detect_secrets(content)
    detected_types = [detection["type"] for detection in detections]

    assert detected_types == ["GitHub Token", "AWS Access Key ID", "OpenAI API Key"]
    starts = [detection["start"] for detection in detections]
    assert starts == sorted(starts)


def test_overlapping_matches_keep_the_first_pattern_in_priority_order():
    # "API_KEY=<openai key>" matches both the OpenAI pattern and the generic
    # assignment pattern over the same characters. The OpenAI pattern is
    # declared earlier, so it should win and the generic match should be
    # dropped as an overlap rather than double-counted.
    content = f"API_KEY={fake_openai_key()}"

    detections = detect_secrets(content)

    assert len(detections) == 1
    assert detections[0]["type"] == "OpenAI API Key"


# ---------------------------------------------------------------------------
# Risk score.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "detections, expected_score",
    [
        pytest.param([], 0, id="no-detections-score-zero"),
        pytest.param([{"severity": "low"}], 15, id="single-low"),
        pytest.param([{"severity": "medium"}], 35, id="single-medium"),
        pytest.param([{"severity": "high"}], 70, id="single-high"),
        pytest.param([{"severity": "critical"}], 90, id="single-critical"),
        pytest.param(
            [{"severity": "high"}, {"severity": "medium"}],
            100,
            id="sum-over-100-is-capped",
        ),
        pytest.param(
            [{"severity": "critical"}, {"severity": "critical"}],
            100,
            id="two-critical-is-capped-at-100",
        ),
    ],
)
def test_calculate_risk_score(detections, expected_score):
    assert calculate_risk_score(detections) == expected_score


# ---------------------------------------------------------------------------
# Masking keeps unrelated surrounding text intact.
# ---------------------------------------------------------------------------


def test_mask_secrets_preserves_surrounding_text_and_formatting():
    secret = fake_openai_key()
    content = f"Header line\nAPI call token: {secret} <-- rest of line!\nFooter line"

    detections = detect_secrets(content)
    sanitized = mask_secrets(content, detections)

    assert sanitized == (
        "Header line\nAPI call token: [REDACTED] <-- rest of line!\nFooter line"
    )
