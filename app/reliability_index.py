from __future__ import annotations

import html
import sqlite3
from typing import Callable

from fastapi import FastAPI
from fastapi.responses import HTMLResponse


def install_reliability_index(app: FastAPI, *, db_factory: Callable[[], sqlite3.Connection]) -> None:
    @app.get("/reliability", response_class=HTMLResponse, include_in_schema=False)
    def reliability_index() -> str:
        with db_factory() as connection:
            projects = [dict(r) for r in connection.execute(
                "SELECT p.id,p.name,p.latest_sha,dt.server_id,s.name server_name FROM projects p LEFT JOIN deployment_targets dt ON dt.project_id=p.id LEFT JOIN servers s ON s.id=dt.server_id ORDER BY p.name"
            ).fetchall()]
        cards = "".join(
            f"<a class='card' href='/projects/{p['id']}/reliability'><h2>{html.escape(str(p['name']))}</h2>"
            f"<p>{html.escape(str(p.get('server_name') or 'No deployment target'))}</p>"
            f"<code>{html.escape(str(p.get('latest_sha') or 'not synced')[:12])}</code><span>Open Release / Drift / DR →</span></a>"
            for p in projects
        ) or "<div class='card'><h2>No projects registered</h2></div>"
        return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Reliability Center</title><style>body{{margin:0;background:#f5f8f6;color:#17231f;font:14px system-ui}}.top{{background:#173c38;color:#fff;padding:18px 24px;display:flex;justify-content:space-between}}.top a{{color:#fff}}.wrap{{max-width:1200px;margin:auto;padding:26px}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}.card{{display:block;text-decoration:none;color:inherit;background:#fff;border:1px solid #dfe7e2;border-radius:16px;padding:18px}}.card span{{display:block;margin-top:20px;color:#285b55;font-weight:800}}code{{color:#52655e}}@media(max-width:850px){{.grid{{grid-template-columns:1fr}}}}</style></head><body><div class='top'><b>Custom GitHub · Reliability Center</b><a href='/'>Infrastructure</a></div><div class='wrap'><h1>Release, Drift & Recovery</h1><p>Select an application project to inspect immutable releases, detect production drift, perform manual rollback, or run a real backup restore rehearsal on an unused VPS.</p><div class='grid'>{cards}</div></div></body></html>"""
