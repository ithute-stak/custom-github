import base64

import pytest

from app.github_secret_write import encrypt_github_secret


def test_invalid_github_secret_public_key_fails_closed() -> None:
    with pytest.raises(ValueError, match="invalid public key"):
        encrypt_github_secret("not-base64!!", "plaintext-must-not-leak")

    too_short = base64.b64encode(b"short-key").decode("ascii")
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt_github_secret(too_short, "plaintext-must-not-leak")
