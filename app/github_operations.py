from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
    except Exception:
        return None


def parse_github_repository(url: str) -> tuple[str, str]:
    value = url.strip()
    prefix = "https://github.com/"
    if not value.startswith(prefix):
        raise ValueError("Only https://github.com repositories are supported")
    tail = value[len(prefix) :]
    if tail.endswith(".git"):
        tail = tail[:-4]
    parts = tail.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("GitHub repository URL must be https://github.com/OWNER/REPO")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if any(any(ch not in allowed for ch in part) for part in parts):
        raise ValueError("GitHub owner/repository contains unsupported characters")
    return parts[0], parts[1]


class GitHubAPIError(RuntimeError):
    def __init__(self, status: int, message: str, *, rate_remaining: str | None = None):
        self.status = status
        self.rate_remaining = rate_remaining
        super().__init__(message)


class GitHubAPI:
    def __init__(self, token: str | None = None, timeout: int = 20):
        self.token = token or os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip() or None
        self.timeout = timeout
        self.rate: dict[str, str | None] = {"limit": None, "remaining": None, "reset": None, "resource": None}

    def get(self, path: str) -> Any:
        request = Request(
            "https://api.github.com" + path,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "custom-github-control-plane",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                self._capture_rate(response.headers)
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except HTTPError as exc:
            self._capture_rate(exc.headers)
            try:
                body = json.loads(exc.read().decode("utf-8"))
                message = str(body.get("message") or exc.reason)
            except Exception:
                message = str(exc.reason)
            raise GitHubAPIError(exc.code, message, rate_remaining=self.rate.get("remaining")) from exc
        except URLError as exc:
            raise GitHubAPIError(503, f"GitHub API unavailable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise GitHubAPIError(504, "GitHub API request timed out") from exc

    def _capture_rate(self, headers: Any) -> None:
        if not headers:
            return
        self.rate = {
            "limit": headers.get("X-RateLimit-Limit"),
            "remaining": headers.get("X-RateLimit-Remaining"),
            "reset": headers.get("X-RateLimit-Reset"),
            "resource": headers.get("X-RateLimit-Resource"),
        }


def _run_git(path: Path, args: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=path,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def inspect_local_repository(project: Any) -> dict[str, Any]:
    path = Path(str(project["workspace_path"]))
    result: dict[str, Any] = {
        "exists": path.exists(),
        "workspace_path": str(path),
        "branch": None,
        "head_sha": None,
        "origin": None,
        "dirty_files": None,
        "ahead": None,
        "behind": None,
    }
    if not path.exists() or not (path / ".git").exists():
        return result

    commands = {
        "branch": ["rev-parse", "--abbrev-ref", "HEAD"],
        "head_sha": ["rev-parse", "HEAD"],
        "origin": ["remote", "get-url", "origin"],
        "status": ["status", "--porcelain"],
    }
    outputs: dict[str, str | None] = {}
    for key, args in commands.items():
        code, output = _run_git(path, args)
        outputs[key] = output if code == 0 else None
    result["branch"] = outputs["branch"]
    result["head_sha"] = outputs["head_sha"]
    result["origin"] = outputs["origin"]
    result["dirty_files"] = len([line for line in (outputs["status"] or "").splitlines() if line.strip()])

    branch = str(project["branch"])
    code, output = _run_git(path, ["rev-list", "--left-right", "--count", f"HEAD...origin/{branch}"])
    if code == 0:
        try:
            ahead, behind = output.split()[:2]
            result["ahead"] = int(ahead)
            result["behind"] = int(behind)
        except Exception:
            pass
    return result


def _remote_snapshot(client: GitHubAPI, owner: str, repo: str, branch: str) -> dict[str, Any]:
    base = f"/repos/{owner}/{repo}"
    repository = client.get(base)
    branches = client.get(base + "/branches?per_page=50")
    commits = client.get(base + f"/commits?sha={branch}&per_page=25")
    pulls = client.get(base + "/pulls?state=open&per_page=25")
    workflow_payload = client.get(base + "/actions/runs?per_page=25")
    releases = client.get(base + "/releases?per_page=10")

    return {
        "repository": {
            "id": repository.get("id"),
            "full_name": repository.get("full_name"),
            "private": repository.get("private"),
            "archived": repository.get("archived"),
            "disabled": repository.get("disabled"),
            "default_branch": repository.get("default_branch"),
            "description": repository.get("description"),
            "language": repository.get("language"),
            "visibility": repository.get("visibility"),
            "open_issues_count": repository.get("open_issues_count"),
            "forks_count": repository.get("forks_count"),
            "stargazers_count": repository.get("stargazers_count"),
            "size_kb": repository.get("size"),
            "updated_at": repository.get("updated_at"),
            "pushed_at": repository.get("pushed_at"),
            "html_url": repository.get("html_url"),
        },
        "branches": [
            {
                "name": item.get("name"),
                "sha": (item.get("commit") or {}).get("sha"),
                "protected": bool(item.get("protected")),
            }
            for item in (branches or [])
        ],
        "commits": [
            {
                "sha": item.get("sha"),
                "message": (((item.get("commit") or {}).get("message") or "").splitlines() or [""])[0],
                "author": ((item.get("author") or {}).get("login") or ((item.get("commit") or {}).get("author") or {}).get("name")),
                "date": (((item.get("commit") or {}).get("author") or {}).get("date")),
                "html_url": item.get("html_url"),
            }
            for item in (commits or [])
        ],
        "pull_requests": [
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "draft": bool(item.get("draft")),
                "author": ((item.get("user") or {}).get("login")),
                "head": ((item.get("head") or {}).get("ref")),
                "base": ((item.get("base") or {}).get("ref")),
                "updated_at": item.get("updated_at"),
                "html_url": item.get("html_url"),
            }
            for item in (pulls or [])
        ],
        "workflow_runs": [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "event": item.get("event"),
                "branch": item.get("head_branch"),
                "sha": item.get("head_sha"),
                "status": item.get("status"),
                "conclusion": item.get("conclusion"),
                "run_number": item.get("run_number"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "html_url": item.get("html_url"),
            }
            for item in ((workflow_payload or {}).get("workflow_runs") or [])
        ],
        "releases": [
            {
                "id": item.get("id"),
                "tag_name": item.get("tag_name"),
                "name": item.get("name"),
                "draft": bool(item.get("draft")),
                "prerelease": bool(item.get("prerelease")),
                "published_at": item.get("published_at"),
                "html_url": item.get("html_url"),
            }
            for item in (releases or [])
        ],
        "rate_limit": dict(client.rate),
    }


def install_github_operations_routes(
    app: FastAPI,
    *,
    db_factory: Callable,
    project_lookup: Callable[[int], Any],
    audit_fn: Callable[[str, str, int | None, str], None],
    api_factory: Callable[[], GitHubAPI] | None = None,
) -> None:
    with db_factory() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS github_repo_snapshots (
                project_id INTEGER PRIMARY KEY,
                repository_full_name TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                error TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )
            """
        )

    def cached(project_id: int) -> dict[str, Any] | None:
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM github_repo_snapshots WHERE project_id=?", (project_id,)).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            return None
        payload["captured_at"] = row["captured_at"]
        payload["cache_age_seconds"] = _age_seconds(row["captured_at"])
        return payload

    @app.get("/github", response_class=HTMLResponse, include_in_schema=False)
    def github_index() -> str:
        return GITHUB_INDEX_HTML

    @app.get("/projects/{project_id}/github", response_class=HTMLResponse, include_in_schema=False)
    def github_project_page(project_id: int) -> str:
        project = project_lookup(project_id)
        return GITHUB_PROJECT_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/api/github/status")
    def github_status() -> dict[str, Any]:
        token = os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip()
        with db_factory() as connection:
            snapshots = int(connection.execute("SELECT COUNT(*) FROM github_repo_snapshots").fetchone()[0])
        return {
            "provider": "github.com",
            "mode": "authenticated" if token else "anonymous",
            "token_configured": bool(token),
            "credential_storage": "environment" if token else "none",
            "snapshots": snapshots,
            "mutation_enabled": False,
        }

    @app.get("/api/github/projects")
    def github_projects() -> list[dict[str, Any]]:
        with db_factory() as connection:
            rows = connection.execute(
                """
                SELECT p.id,p.name,p.github_url,p.branch,p.latest_sha,s.captured_at
                FROM projects p LEFT JOIN github_repo_snapshots s ON s.project_id=p.id
                ORDER BY p.name
                """
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                owner, repo = parse_github_repository(item["github_url"])
                item["repository_full_name"] = f"{owner}/{repo}"
                item["supported"] = True
            except ValueError:
                item["repository_full_name"] = None
                item["supported"] = False
            item["snapshot_age_seconds"] = _age_seconds(item.get("captured_at"))
            result.append(item)
        return result

    @app.get("/api/projects/{project_id}/github/overview")
    def github_overview(project_id: int, refresh: bool = Query(default=False)) -> dict[str, Any]:
        project = project_lookup(project_id)
        try:
            owner, repo = parse_github_repository(str(project["github_url"]))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        local = inspect_local_repository(project)
        existing = cached(project_id)
        if existing and not refresh and (existing.get("cache_age_seconds") or 999999) <= 60:
            return {
                "project_id": project_id,
                "project_name": project["name"],
                "repository_full_name": f"{owner}/{repo}",
                "source": "cache",
                "stale": False,
                "local": local,
                **existing,
            }

        client = api_factory() if api_factory else GitHubAPI()
        try:
            remote = _remote_snapshot(client, owner, repo, str(project["branch"]))
            captured_at = _now()
            with db_factory() as connection:
                connection.execute(
                    """
                    INSERT INTO github_repo_snapshots(project_id,repository_full_name,payload_json,captured_at,error)
                    VALUES(?,?,?,?,NULL)
                    ON CONFLICT(project_id) DO UPDATE SET
                      repository_full_name=excluded.repository_full_name,
                      payload_json=excluded.payload_json,
                      captured_at=excluded.captured_at,
                      error=NULL
                    """,
                    (project_id, f"{owner}/{repo}", json.dumps(remote), captured_at),
                )
            audit_fn("github.snapshot.refreshed", "project", project_id, f"Refreshed GitHub state for {owner}/{repo}")
            return {
                "project_id": project_id,
                "project_name": project["name"],
                "repository_full_name": f"{owner}/{repo}",
                "source": "live",
                "stale": False,
                "captured_at": captured_at,
                "cache_age_seconds": 0,
                "local": local,
                **remote,
            }
        except GitHubAPIError as exc:
            if existing:
                return {
                    "project_id": project_id,
                    "project_name": project["name"],
                    "repository_full_name": f"{owner}/{repo}",
                    "source": "cache",
                    "stale": True,
                    "refresh_error": str(exc),
                    "refresh_status": exc.status,
                    "local": local,
                    **existing,
                }
            status = 502 if exc.status >= 500 else exc.status
            raise HTTPException(status_code=status, detail=f"GitHub API: {exc}") from exc


GITHUB_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Operations</title><style>body{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}.wrap{max-width:1220px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:18px;margin:12px 0}.btn{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;text-decoration:none}.muted{color:#93a4bb}.good{color:#69dda4}.warn{color:#ffd76e}.repo{display:grid;grid-template-columns:1.2fr .8fr .7fr .7fr 120px;gap:12px;align-items:center;border-top:1px solid #26364c;padding:13px 0}@media(max-width:800px){.repo{grid-template-columns:1fr}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>SOURCE CONTROL</div><h1>GitHub Operations Center</h1><div class='muted'>Repository state, branches, commits, pull requests, Actions and releases. Remote mutations remain intentionally disabled in this tranche.</div></div><a class='btn' href='/'>Infrastructure</a></div><div class='card' id='status'>Loading integration status…</div><div class='card'><div class='row'><h2>Registered repositories</h2><button class='btn' onclick='load()'>Refresh list</button></div><div id='repos'></div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function load(){const [s,p]=await Promise.all([fetch('/api/github/status').then(r=>r.json()),fetch('/api/github/projects').then(r=>r.json())]);document.getElementById('status').innerHTML=`<div class='row'><div><b>${e(s.provider)}</b><div class='muted'>${s.mode==='authenticated'?'Authenticated API access':'Anonymous API access — configure token for private repos and higher rate limits'}</div></div><div><span class='${s.token_configured?'good':'warn'}'>${s.token_configured?'TOKEN CONFIGURED':'NO TOKEN'}</span> · ${s.snapshots} cached snapshot(s)</div></div>`;document.getElementById('repos').innerHTML=p.length?p.map(x=>`<div class='repo'><div><b>${e(x.name)}</b><div class='muted'>${e(x.repository_full_name||x.github_url)}</div></div><div>${e(x.branch)}</div><div>${x.latest_sha?e(x.latest_sha.slice(0,12)):'—'}</div><div>${x.captured_at?Math.round(x.snapshot_age_seconds||0)+'s cache':'No snapshot'}</div><div>${x.supported?`<a class='btn' href='/projects/${x.id}/github'>Open</a>`:'Unsupported'}</div></div>`).join(''):'<div class=muted>No repositories registered.</div>'}load().catch(err=>document.getElementById('status').textContent=err.message)</script></body></html>"""


GITHUB_PROJECT_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub · __PROJECT_NAME__</title><style>body{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}.wrap{max-width:1280px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:17px;margin:12px 0}.metric{font-size:27px;font-weight:800}.btn{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;text-decoration:none;cursor:pointer}.muted{color:#93a4bb}.good{color:#69dda4}.warn{color:#ffd76e}.bad{color:#ff707c}.table{width:100%;border-collapse:collapse}.table td,.table th{padding:10px;border-top:1px solid #26364c;text-align:left;vertical-align:top}.scroll{overflow:auto}@media(max-width:850px){.grid{grid-template-columns:1fr 1fr}}@media(max-width:520px){.grid{grid-template-columns:1fr}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>GITHUB / __PROJECT_NAME__</div><h1 id='title'>__PROJECT_NAME__</h1><div class='muted' id='subtitle'>Loading GitHub state…</div></div><div><a class='btn' href='/github'>All repositories</a> <button class='btn' onclick='load(true)'>↻ Refresh GitHub</button></div></div><div class='grid' id='metrics'></div><div class='card' id='local'></div><div class='card'><h2>Branches</h2><div class='scroll' id='branches'></div></div><div class='card'><h2>Open pull requests</h2><div class='scroll' id='prs'></div></div><div class='card'><h2>GitHub Actions</h2><div class='scroll' id='runs'></div></div><div class='card'><h2>Recent commits</h2><div class='scroll' id='commits'></div></div><div class='card'><h2>Releases</h2><div class='scroll' id='releases'></div></div></div><script>const ID=__PROJECT_ID__;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const table=(heads,rows)=>`<table class=table><thead><tr>${heads.map(h=>`<th>${e(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;async function load(refresh=false){document.getElementById('subtitle').textContent='Loading…';const r=await fetch(`/api/projects/${ID}/github/overview?refresh=${refresh}`);const x=await r.json();if(!r.ok)throw new Error(x.detail||'GitHub request failed');document.getElementById('subtitle').innerHTML=`${e(x.repository_full_name)} · <span class='${x.stale?'warn':'good'}'>${x.source.toUpperCase()}${x.stale?' / STALE':''}</span>${x.refresh_error?' · '+e(x.refresh_error):''}`;const repo=x.repository||{};document.getElementById('metrics').innerHTML=[[repo.visibility||'—','Visibility'],[(x.branches||[]).length,'Branches'],[(x.pull_requests||[]).length,'Open PRs'],[(x.workflow_runs||[]).filter(a=>a.status!=='completed'||a.conclusion!=='success').length,'Action attention']].map(m=>`<div class=card><div class=metric>${e(m[0])}</div><div class=muted>${e(m[1])}</div></div>`).join('');const l=x.local||{};document.getElementById('local').innerHTML=`<div class=row><div><h2>Local checkout</h2><div class=muted>${e(l.workspace_path)}</div></div><div>${l.exists?'<span class=good>AVAILABLE</span>':'<span class=warn>NOT CLONED</span>'}</div></div><div class=grid><div><b>${e(l.branch||'—')}</b><div class=muted>Branch</div></div><div><b>${e((l.head_sha||'').slice(0,12)||'—')}</b><div class=muted>HEAD</div></div><div><b>${e(l.dirty_files??'—')}</b><div class=muted>Dirty files</div></div><div><b>${e(l.ahead??'—')} / ${e(l.behind??'—')}</b><div class=muted>Ahead / behind</div></div></div>`;document.getElementById('branches').innerHTML=table(['Branch','SHA','Protection'],(x.branches||[]).map(b=>`<tr><td>${e(b.name)}</td><td>${e((b.sha||'').slice(0,12))}</td><td>${b.protected?'<span class=good>Protected</span>':'<span class=warn>Unprotected</span>'}</td></tr>`));document.getElementById('prs').innerHTML=table(['PR','Title','Head → Base','Author'],(x.pull_requests||[]).map(p=>`<tr><td><a href='${e(p.html_url)}' target=_blank>#${e(p.number)}</a>${p.draft?' · Draft':''}</td><td>${e(p.title)}</td><td>${e(p.head)} → ${e(p.base)}</td><td>${e(p.author)}</td></tr>`));document.getElementById('runs').innerHTML=table(['Run','Workflow','Branch','Status'],(x.workflow_runs||[]).map(a=>`<tr><td><a href='${e(a.html_url)}' target=_blank>#${e(a.run_number)}</a></td><td>${e(a.name)}</td><td>${e(a.branch)}</td><td class='${a.status==='completed'&&a.conclusion==='success'?'good':a.status==='completed'?'bad':'warn'}'>${e(a.status)} / ${e(a.conclusion||'—')}</td></tr>`));document.getElementById('commits').innerHTML=table(['SHA','Message','Author','Date'],(x.commits||[]).map(c=>`<tr><td><a href='${e(c.html_url)}' target=_blank>${e((c.sha||'').slice(0,12))}</a></td><td>${e(c.message)}</td><td>${e(c.author)}</td><td>${e(c.date||'')}</td></tr>`));document.getElementById('releases').innerHTML=table(['Tag','Name','Published'],(x.releases||[]).map(a=>`<tr><td><a href='${e(a.html_url)}' target=_blank>${e(a.tag_name)}</a></td><td>${e(a.name||'—')}${a.prerelease?' · prerelease':''}${a.draft?' · draft':''}</td><td>${e(a.published_at||'—')}</td></tr>`))}load(false).catch(err=>document.getElementById('subtitle').innerHTML=`<span class=bad>${e(err.message)}</span>`)</script></body></html>"""
