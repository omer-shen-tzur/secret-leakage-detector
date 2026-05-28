from pathlib import Path

ALLOWED_EXTENSIONS = {
    ".txt",
    ".env",
    ".json",
    ".md",
    ".py",
    ".js",
    ".ts",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
}


def is_allowed_file(filename: str | None) -> bool:
    if not filename:
        return False

    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def decode_text_file(content: bytes) -> str:
    if b"\x00" in content:
        raise ValueError("Binary files are not supported.")

    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("File must be readable as UTF-8 text.") from exc
