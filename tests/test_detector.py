from app.detector import detect_secrets, mask_secrets, placeholder_scan


def test_detects_required_secret_types():
    content = "\n".join(
        [
            "aws_key = [REDACTED]",
            "AWS_SECRET_ACCESS_KEY=[REDACTED]",
            "OPENAI_API_KEY=[REDACTED]",
            "GITHUB_TOKEN=[REDACTED]",
            "jwt=[REDACTED]",
            "password=[REDACTED]",
            "DB_PASSWORD=[REDACTED]",
            "API_KEY=[REDACTED]",
            "SECRET=[REDACTED]",
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
    content = "OPENAI_API_KEY=[REDACTED]"

    detection = detect_secrets(content)[0]

    assert detection == {
        "type": "OpenAI API Key",
        "severity": "critical",
        "start": content.index("sk-proj-"),
        "end": len(content),
        "masked_value": "[REDACTED]",
    }


def test_masks_secret_values_and_keeps_surrounding_text_readable():
    content = "before password=[REDACTED] after"
    detections = detect_secrets(content)

    sanitized = mask_secrets(content, detections)

    assert sanitized == "before password=[REDACTED] after"


def test_scan_content_returns_sanitized_output_and_score():
    content = "token [REDACTED]"

    result = placeholder_scan("text", content)

    assert result["detected_count"] == 1
    assert result["risk_score"] == 90
    assert result["detected_types"] == ["OpenAI API Key"]
    assert result["sanitized_output"] == "token [REDACTED]"


def test_aws_secret_assignment_is_not_double_counted_as_generic_secret():
    content = "AWS_SECRET_ACCESS_KEY=[REDACTED]"

    detections = detect_secrets(content)

    assert len(detections) == 1
    assert detections[0]["type"] == "AWS Secret Access Key"