from pathlib import Path


def test_pytest_is_scoped_to_control_plane_tests() -> None:
    config = Path("pytest.ini").read_text(encoding="utf-8")
    assert "testpaths = tests" in config
    assert "norecursedirs = data .venv" in config


def test_local_verifier_does_not_collect_runtime_workspaces() -> None:
    script = Path("scripts/verify-local.sh").read_text(encoding="utf-8")
    assert "python -m pytest -q tests" in script
    assert "python -m pytest -q\n" not in script


def test_ci_does_not_collect_runtime_workspaces() -> None:
    workflow = Path(".github/workflows/verify.yml").read_text(encoding="utf-8")
    assert "run: python -m pytest -q tests" in workflow
    assert "- feature/control-plane-mvp" in workflow
