from __future__ import annotations

import base64
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Query

from app.deployment import ssh_command
from app.vps import normalize_remote_path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def install_file_manager_enhancements_routes(
    app: FastAPI,
    *,
    server_lookup: Callable[[int], sqlite3.Row],
) -> None:
    """Add read-only directory usage inspection used by the VPS file manager."""

    @app.get("/api/vps/servers/{server_id}/files/usage")
    def directory_usage(server_id: int, path: str = Query(default="/")) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(path)
        quoted = shlex.quote(normalized)
        script = f"""
set -u
path={quoted}
[ -d "$path" ] || {{ printf 'Not a directory: %s\\n' "$path" >&2; exit 44; }}
if [ "$(id -u)" -eq 0 ]; then
  mode=root
elif sudo -n true >/dev/null 2>&1; then
  mode=sudo
else
  mode=user
fi
find "$path" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | \
  xargs -0 -r -n1 -P3 bash -c '
    mode="$1"
    item="$2"
    if [ "$mode" = sudo ]; then
      output=$(timeout 60s sudo -n du -x -B1 -s -- "$item" 2>/dev/null || true)
    else
      output=$(timeout 60s du -x -B1 -s -- "$item" 2>/dev/null || true)
    fi
    bytes=${{output%%$'"'"'\\t'"'"'*}}
    case "$bytes" in
      ""|*[!0-9]*) status=unavailable; bytes=0 ;;
      *) status=ok ;;
    esac
    encoded=$(printf "%s" "$item" | base64 -w0)
    printf "%s\\t%s\\t%s\\n" "$encoded" "$bytes" "$status"
  ' _ "$mode"
""".strip()
        code, output = ssh_command(server, f"bash -lc {shlex.quote(script)}", timeout=150)
        if code != 0:
            message = output.strip()[-4000:] or f"Folder size scan failed with exit code {code}"
            raise HTTPException(status_code=502, detail=message)

        usage: list[dict[str, Any]] = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            try:
                item_path = base64.b64decode(parts[0].encode("ascii"), validate=True).decode("utf-8", errors="replace")
            except Exception:
                continue
            try:
                byte_count = int(parts[1])
            except ValueError:
                byte_count = 0
            usage.append({"path": item_path, "bytes": byte_count, "status": parts[2]})

        usage.sort(key=lambda item: item["path"].lower())
        return {
            "path": normalized,
            "usage": usage,
            "folders": len(usage),
            "bytes": sum(item["bytes"] for item in usage if item["status"] == "ok"),
            "calculated_at": _utc_now(),
        }


FILE_MANAGER_ENHANCEMENT = r"""
<style id="file-manager-enhancement-style">
  .file-view-toggle{display:inline-flex;border:1px solid var(--line);border-radius:9px;overflow:hidden;background:#fff}
  .file-view-toggle .btn{border:0;border-radius:0;box-shadow:none;min-width:38px}
  .file-view-toggle .btn.active{background:var(--brand);color:#fff}
  .file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;padding:14px}
  .file-grid[hidden],.file-list-pane[hidden]{display:none!important}
  .file-tile{border:1px solid var(--line);border-radius:13px;background:#fff;padding:14px;min-width:0;transition:.15s ease;display:flex;flex-direction:column;gap:10px}
  .file-tile:hover{border-color:#b8c9c0;box-shadow:0 8px 24px rgba(18,50,40,.08);transform:translateY(-1px)}
  .file-tile-main{display:flex;gap:11px;align-items:flex-start;min-width:0;cursor:default}
  .file-tile.folder .file-tile-main{cursor:pointer}
  .file-tile-icon{width:44px;height:44px;flex:0 0 44px;border-radius:12px;background:#eef5f1;display:grid;place-items:center;font-size:20px}
  .file-tile.folder .file-tile-icon{background:#fff4cf}
  .file-tile-copy{min-width:0;flex:1}.file-tile-copy b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}
  .file-tile-size{font-size:11px;font-weight:800;margin-top:5px;color:var(--brand2)}
  .file-tile-meta{font-size:9px;color:var(--muted);line-height:1.45;margin-top:4px;word-break:break-word}
  .file-tile-actions{display:flex;gap:5px;flex-wrap:wrap;margin-top:auto;padding-top:4px;border-top:1px solid #eef2ef}
  .usage-loading{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:10px}
  .usage-loading:before{content:"";width:9px;height:9px;border:1.5px solid #b5c2bc;border-top-color:var(--brand2);border-radius:50%;animation:spin .7s linear infinite}
  .file-size-strong{font-weight:760;color:#33443c}
  @media(max-width:700px){.file-grid{grid-template-columns:repeat(2,minmax(0,1fr));padding:10px}.file-tile{padding:11px}.file-tile-icon{width:38px;height:38px;flex-basis:38px}}
  @media(max-width:480px){.file-grid{grid-template-columns:1fr}}
</style>
<script id="file-manager-enhancement-script">
(() => {
  const section = document.getElementById('section-files');
  if (!section || section.dataset.enhancedFileManager === '1') return;
  section.dataset.enhancedFileManager = '1';

  let entries = [];
  let usage = new Map();
  let usageStatus = new Map();
  let requestToken = 0;
  let viewMode = localStorage.getItem('custom-github.file-view') || 'list';
  let sortMode = localStorage.getItem('custom-github.file-sort') || 'name';

  const toolbar = section.querySelector('.toolbar');
  toolbar.insertAdjacentHTML('beforeend', `
    <select id="fileSort" class="select" title="Sort files">
      <option value="name">Sort: Name</option>
      <option value="size">Sort: Size</option>
      <option value="modified">Sort: Modified</option>
    </select>
    <button id="fileRecalculateBtn" class="btn" type="button" title="Recalculate folder disk usage">◴ Folder sizes</button>
    <div class="file-view-toggle" aria-label="File view">
      <button id="fileListViewBtn" class="btn tiny" type="button" title="List view">☷</button>
      <button id="fileTileViewBtn" class="btn tiny" type="button" title="Tile view">▦</button>
    </div>`);

  const card = section.querySelector('.card');
  const cardHead = card.querySelector('.cardhead');
  const count = document.getElementById('fileCount');
  const usageBadge = document.createElement('span');
  usageBadge.id = 'fileUsageState';
  usageBadge.className = 'tag';
  usageBadge.textContent = 'Folder sizes idle';
  count.parentNode.insertBefore(usageBadge, count);

  const tableWrap = card.querySelector('.tablewrap');
  tableWrap.id = 'fileListPane';
  tableWrap.classList.add('file-list-pane');
  const sizeHeader = tableWrap.querySelector('thead th:nth-child(2)');
  if (sizeHeader) sizeHeader.textContent = 'Disk usage';
  tableWrap.insertAdjacentHTML('afterend', '<div id="fileTilePane" class="file-grid" hidden></div>');

  function itemSize(item) {
    if (item.kind !== 'directory') return Number(item.size || 0);
    return usage.has(item.path) ? Number(usage.get(item.path) || 0) : -1;
  }

  function sizeHtml(item) {
    if (item.kind !== 'directory') return `<span class="file-size-strong">${fmtBytes(item.size)}</span>`;
    if (usage.has(item.path)) return `<span class="file-size-strong">${fmtBytes(usage.get(item.path))}</span>`;
    if (usageStatus.get(item.path) === 'unavailable') return '<span class="sub">Unavailable</span>';
    return '<span class="usage-loading">Calculating…</span>';
  }

  function sortedEntries() {
    const list = [...entries];
    list.sort((a,b) => {
      if (a.kind === 'directory' && b.kind !== 'directory') return -1;
      if (a.kind !== 'directory' && b.kind === 'directory') return 1;
      if (sortMode === 'size') return itemSize(b) - itemSize(a) || a.name.localeCompare(b.name);
      if (sortMode === 'modified') return Number(b.modified_at||0) - Number(a.modified_at||0) || a.name.localeCompare(b.name);
      return a.name.localeCompare(b.name, undefined, {numeric:true,sensitivity:'base'});
    });
    return list;
  }

  function actionButtons(item) {
    const primary = item.kind === 'directory'
      ? `<button class="btn tiny" onclick='loadFiles(${JSON.stringify(item.path)})'>Open</button>`
      : item.kind === 'file'
        ? `<button class="btn tiny" onclick='editFile(${JSON.stringify(item.path)})'>Edit</button>`
        : '';
    return `${primary}<button class="btn tiny" onclick='renamePath(${JSON.stringify(item.path)})'>Move</button><button class="btn tiny danger" onclick='trashPath(${JSON.stringify(item.path)})'>Trash</button>`;
  }

  function renderList() {
    const rows = document.getElementById('fileRows');
    if (!entries.length) {
      rows.innerHTML = '<tr><td colspan="6"><div class="empty">This directory is empty.</div></td></tr>';
      return;
    }
    rows.innerHTML = sortedEntries().map(item => `
      <tr>
        <td><div class="filename"><span class="fileico ${item.kind==='directory'?'folder':''}">${item.kind==='directory'?'▰':item.kind==='link'?'↗':'▤'}</span><b title="${esc(item.path)}">${esc(item.name)}</b></div></td>
        <td data-file-size="${esc(item.path)}">${sizeHtml(item)}</td>
        <td><span class="mono">${esc(item.permissions)}</span> <span class="tag">${esc(item.mode)}</span></td>
        <td>${esc(item.owner)}:${esc(item.group)}</td>
        <td>${fmtTime(item.modified_at)}</td>
        <td><div class="actions">${actionButtons(item)}</div></td>
      </tr>`).join('');
  }

  function renderTiles() {
    const pane = document.getElementById('fileTilePane');
    if (!entries.length) {
      pane.innerHTML = '<div class="empty" style="grid-column:1/-1">This directory is empty.</div>';
      return;
    }
    pane.innerHTML = sortedEntries().map(item => `
      <article class="file-tile ${item.kind==='directory'?'folder':''}" title="${esc(item.path)}">
        <div class="file-tile-main" ${item.kind==='directory'?`ondblclick='loadFiles(${JSON.stringify(item.path)})'`:''}>
          <div class="file-tile-icon">${item.kind==='directory'?'▰':item.kind==='link'?'↗':'▤'}</div>
          <div class="file-tile-copy"><b>${esc(item.name)}</b><div class="file-tile-size" data-file-size="${esc(item.path)}">${sizeHtml(item)}</div><div class="file-tile-meta">${esc(item.owner)}:${esc(item.group)} · ${esc(item.permissions)}<br>${fmtTime(item.modified_at)}</div></div>
        </div>
        <div class="file-tile-actions">${actionButtons(item)}</div>
      </article>`).join('');
  }

  function render() { renderList(); renderTiles(); }

  function setView(mode) {
    viewMode = mode === 'tile' ? 'tile' : 'list';
    localStorage.setItem('custom-github.file-view', viewMode);
    document.getElementById('fileListPane').hidden = viewMode !== 'list';
    document.getElementById('fileTilePane').hidden = viewMode !== 'tile';
    document.getElementById('fileListViewBtn').classList.toggle('active', viewMode === 'list');
    document.getElementById('fileTileViewBtn').classList.toggle('active', viewMode === 'tile');
  }

  async function loadUsage(path, token, force=false) {
    if (token !== requestToken) return;
    usageBadge.className = 'tag amber';
    usageBadge.innerHTML = '<span class="usage-loading">Calculating folder sizes</span>';
    const button = document.getElementById('fileRecalculateBtn');
    button.disabled = true;
    button.textContent = '◴ Calculating…';
    try {
      const data = await api(`/api/vps/servers/${serverId}/files/usage?path=${encodeURIComponent(path)}${force?'&refresh=1':''}`);
      if (token !== requestToken || path !== currentPath) return;
      usage = new Map(); usageStatus = new Map();
      for (const item of data.usage || []) {
        usageStatus.set(item.path, item.status);
        if (item.status === 'ok') usage.set(item.path, Number(item.bytes || 0));
      }
      usageBadge.className = 'tag green';
      usageBadge.textContent = `${data.folders} folder${data.folders===1?'':'s'} · ${fmtBytes(data.bytes)} total`;
      render();
    } catch (err) {
      if (token !== requestToken) return;
      usageBadge.className = 'tag amber';
      usageBadge.textContent = 'Folder sizes unavailable';
    } finally {
      button.disabled = false;
      button.textContent = '◴ Folder sizes';
    }
  }

  async function enhancedLoadFiles(path='/') {
    const token = ++requestToken;
    const rows = document.getElementById('fileRows');
    rows.innerHTML = skeletonRows(6);
    document.getElementById('fileTilePane').innerHTML = Array.from({length:8},()=>'<div class="file-tile"><div class="skeleton" style="height:44px"></div><div class="skeleton"></div><div class="skeleton"></div></div>').join('');
    usage = new Map(); usageStatus = new Map();
    usageBadge.className = 'tag'; usageBadge.textContent = 'Loading folder sizes…';
    try {
      const data = await api(`/api/vps/servers/${serverId}/files?path=${encodeURIComponent(path)}`);
      if (token !== requestToken) return;
      currentPath = data.path;
      entries = data.entries || [];
      document.getElementById('filePath').value = currentPath;
      document.getElementById('fileUpBtn').disabled = currentPath === '/';
      document.getElementById('fileCount').textContent = `${entries.length} items`;
      document.getElementById('fileDirMeta').textContent = `${data.directory?.owner||''} · mode ${data.directory?.mode||'—'} · folder sizes are allocated disk usage`;
      render();
      setView(viewMode);
      void loadUsage(currentPath, token);
    } catch (err) {
      if (token !== requestToken) return;
      rows.innerHTML = `<tr><td colspan="6"><div class="errorbox">${esc(err.message)}</div></td></tr>`;
      document.getElementById('fileTilePane').innerHTML = `<div class="errorbox" style="grid-column:1/-1">${esc(err.message)}</div>`;
      usageBadge.className = 'tag red'; usageBadge.textContent = 'Unable to browse';
    }
  }

  loadFiles = enhancedLoadFiles;
  document.getElementById('fileListViewBtn').onclick = () => setView('list');
  document.getElementById('fileTileViewBtn').onclick = () => setView('tile');
  document.getElementById('fileSort').value = sortMode;
  document.getElementById('fileSort').onchange = event => { sortMode=event.target.value;localStorage.setItem('custom-github.file-sort',sortMode);render(); };
  document.getElementById('fileRecalculateBtn').onclick = () => { const token=++requestToken; render(); void loadUsage(currentPath, token, true); };
  setView(viewMode);
})();
</script>
"""


__all__ = ["FILE_MANAGER_ENHANCEMENT", "install_file_manager_enhancements_routes"]
