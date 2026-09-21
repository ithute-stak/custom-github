from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


# Pytest imports conftest.py before collecting/importing test modules. app.main resolves
# DATA_DIR/DB_PATH at module import time, so the environment must be set here rather than
# inside an individual test module. This guarantees tests never touch the operator's real
# control-plane database, regardless of test collection order.
TEST_SESSION_ROOT = Path(tempfile.mkdtemp(prefix="custom-github-pytest-"))
TEST_DATA_DIR = TEST_SESSION_ROOT / "data"
TEST_WORKSPACE_ROOT = TEST_SESSION_ROOT / "workspaces"

os.environ["CUSTOM_GITHUB_DATA_DIR"] = str(TEST_DATA_DIR)
os.environ["CUSTOM_GITHUB_WORKSPACE_ROOT"] = str(TEST_WORKSPACE_ROOT)


def pytest_sessionfinish(session, exitstatus) -> None:  # type: ignore[no-untyped-def]
    """Remove isolated test state after the complete pytest session."""
    shutil.rmtree(TEST_SESSION_ROOT, ignore_errors=True)
