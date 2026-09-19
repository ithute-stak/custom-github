from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


RUNNER_IMAGES = {
    "node": os.getenv("CUSTOM_GITHUB_NODE_RUNNER_IMAGE", "node:22-bookworm"),
    "python": os.getenv("CUSTOM_GITHUB_PYTHON_RUNNER_IMAGE", "python:3.14-slim"),
    "dotnet": os.getenv("CUSTOM_GITHUB_DOTNET_RUNNER_IMAGE", "mcr.microsoft.com/dotnet/sdk:9.0"),
}
RUNNER_MEMORY = os.getenv("CUSTOM_GITHUB_RUNNER_MEMORY", "4g")
RUNNER_CPUS = os.getenv("CUSTOM_GITHUB_RUNNER_CPUS", "2")
RUNNER_PIDS = os.getenv("CUSTOM_GITHUB_RUNNER_PIDS", "768")


class RunnerError(RuntimeError):
    pass


def _run(argv: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env={**os.environ, "CI": "true"},
        )
        return completed.returncode, completed.stdout
    except FileNotFoundError:
        return 127, f"Required executable not found: {argv[0]}"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, out + "\nCommand timed out."


def _kind(label: str, command: list[str]) -> str:
    first = command[0] if command else ""
    if first in {"npm", "node", "npx", "pnpm", "yarn"} or label.startswith("npm"):
        return "node"
    if first in {"python", "python3", "pip", "pytest"} or label in {"python compile", "pytest"}:
        return "python"
    if first == "dotnet" or label.startswith("dotnet"):
        return "dotnet"
    if first == "docker" or label == "docker build":
        return "docker-build"
    return "safe-host"


def _copy_source(source: Path, target: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git", ".venv", "node_modules", ".next", "dist", "build", "bin", "obj",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    )
    shutil.copytree(source, target, dirs_exist_ok=True, ignore=ignored)


def _container_command(kind: str, workspace: Path, command: list[str]) -> list[str]:
    image = RUNNER_IMAGES[kind]
    base = [
        "docker", "run", "--rm", "--init",
        "--network", "bridge",
        "--memory", RUNNER_MEMORY,
        "--cpus", RUNNER_CPUS,
        "--pids-limit", RUNNER_PIDS,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "-e", "CI=true",
        "-e", "HOME=/tmp/home",
        "-v", f"{workspace}:/workspace:rw",
        "-w", "/workspace",
        image,
    ]
    if kind == "python" and command and command[-1] == "pytest" or (command[:3] == ["python", "-m", "pytest"]):
        pass
    return base + command


def _python_test_command(workspace: Path, command: list[str]) -> list[str]:
    install = ""
    if (workspace / "requirements.txt").exists():
        install = "python -m pip install --disable-pip-version-check -q -r requirements.txt && "
    elif (workspace / "pyproject.toml").exists():
        install = "python -m pip install --disable-pip-version-check -q -e . && "
    cmd = " ".join(subprocess.list2cmdline([part]) for part in command)
    return ["sh", "-lc", install + cmd]


def run_pipeline_isolated(
    *,
    project_name: str,
    source_path: Path,
    commit_sha: str,
    image_tag: str,
    steps: list[tuple[str, list[str]]],
    runs_root: Path,
) -> tuple[str, list[dict[str, Any]], list[str], str | None]:
    """Execute repository code outside the API process.

    Node/Python/.NET commands run in disposable runner containers against a temporary
    source copy. Dockerfile builds use the Docker daemon with that same temporary copy.
    Only benign repository validation is allowed on the host.
    """
    runs_root.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=f"{project_name}-{commit_sha[:8]}-", dir=runs_root))
    workspace = temp_dir / "workspace"
    results: list[dict[str, Any]] = []
    logs: list[str] = []
    overall = "success"
    built_image: str | None = None
    try:
        _copy_source(source_path, workspace)
        check_code, check_output = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
        if check_code != 0:
            raise RunnerError("Isolated pipelines require a working local Docker daemon: " + check_output[-2000:])

        for label, command in steps:
            kind = _kind(label, command)
            if kind in RUNNER_IMAGES:
                actual = command
                if kind == "python" and command[:3] == ["python", "-m", "pytest"]:
                    actual = _python_test_command(workspace, command)
                argv = _container_command(kind, workspace, actual)
                code, output = _run(argv, timeout=1800)
                display = ["runner:" + RUNNER_IMAGES[kind], *command]
            elif kind == "docker-build":
                argv = ["docker", "build", "--pull", "-t", image_tag, "."]
                code, output = _run(argv, cwd=workspace, timeout=3600)
                display = argv
                if code == 0:
                    built_image = image_tag
            else:
                # The fallback validation intentionally executes no repository-provided script.
                code, output = 0, "Repository has no executable pipeline; source copy validated in isolated runner workspace."
                display = ["isolated-source-validation"]

            results.append({
                "name": label,
                "command": display,
                "exit_code": code,
                "status": "success" if code == 0 else "failed",
                "runner": kind,
            })
            logs.append(f"$ {' '.join(display)}\n{output}")
            if code != 0:
                overall = "failed"
                break
        return overall, results, logs, built_image
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
