import pytest

from app.file_utils import decode_text_file, is_allowed_file


@pytest.mark.parametrize(
    "filename, expected",
    [
        pytest.param("secrets.env", True, id="lowercase-env"),
        pytest.param("SECRETS.ENV", True, id="uppercase-env"),
        pytest.param("app.py", True, id="lowercase-py"),
        pytest.param("APP.PY", True, id="uppercase-py"),
        pytest.param("Config.Yml", True, id="mixed-case-yml"),
        pytest.param("archive.zip", False, id="unsupported-extension"),
        pytest.param("no_extension", False, id="no-extension"),
        pytest.param("", False, id="empty-filename"),
        pytest.param(None, False, id="missing-filename"),
    ],
)
def test_is_allowed_file(filename, expected):
    assert is_allowed_file(filename) is expected


def test_decode_text_file_reads_utf8_text():
    assert decode_text_file(b"hello world") == "hello world"


def test_decode_text_file_handles_empty_content():
    assert decode_text_file(b"") == ""


def test_decode_text_file_handles_whitespace_only_content():
    assert decode_text_file(b"   \n\t  ") == "   \n\t  "


def test_decode_text_file_rejects_null_byte_binary_content():
    with pytest.raises(ValueError, match="Binary files are not supported."):
        decode_text_file(b"\x00\x01\x02")


def test_decode_text_file_rejects_non_utf8_content():
    # 0xe9 on its own is not valid UTF-8 (it starts a multi-byte sequence
    # that is never completed), but it contains no null byte either.
    with pytest.raises(ValueError, match="File must be readable as UTF-8 text."):
        decode_text_file(b"caf\xe9 not valid utf-8")
