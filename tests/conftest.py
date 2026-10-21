import pytest

from secret_samples import (
    fake_aws_access_key_id,
    fake_aws_secret_access_key,
    fake_github_token,
    fake_jwt,
    fake_openai_key,
)


@pytest.fixture
def fake_secrets() -> dict[str, str]:
    """One representative fake secret value per detector pattern."""
    return {
        "AWS Access Key ID": fake_aws_access_key_id(),
        "AWS Secret Access Key": fake_aws_secret_access_key(),
        "OpenAI API Key": fake_openai_key(),
        "GitHub Token": fake_github_token(),
        "JWT Token": fake_jwt(),
    }
