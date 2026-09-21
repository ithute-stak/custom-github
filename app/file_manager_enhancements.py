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


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _decode(value: str) -> str:
    return base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8", errors="replace")


def _run_remote_bash(server: dict[str, Any], script: str, *, timeout: int) -> tuple[int, str]:
    """Transmit a bash script losslessly instead of nesting several shell-quote layers."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    command = f"printf '%s' {shlex.quote(encoded)} | base64 -d | bash"
    return ssh_command(server, command, timeout=timeout)


def _directory_error(output: str, fallback_path: str) -> HTTPException:
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) == 5 and parts[0] == "__PATH_ERROR__":
            try:
                requested = _decode(parts[1])
                resolved = _decode(parts[2])
            except Exception:
                requested = fallback_path
                resolved = fallback_path
            exists = parts[3] == "yes"
            remote_type = parts[4] or "unknown"
            if not exists:
                return HTTPException(status_code=404, detail=f"Path does not exist on VPS: {requested}")
            return HTTPException(
                status_code=409,
                detail=f"Path is not a directory on VPS: {requested} (resolved: {resolved}; type: {remote_type})",
            )
    message = output.strip()[-4000:] or f"Unable to inspect directory: {fallback_path}"
    return HTTPException(status_code=502, detail=message)


def install_file_manager_enhancements_routes(
    app: FastAPI,
    *,
    server_lookup: Callable[[int], sqlite3.Row],
) -> None:
    """Install authoritative read-only browse/usage routes used by the VPS file manager."""

    @app.get("/api/vps/servers/{server_id}/files/browse")
    def browse_directory(server_id: int, path: str = Query(default="/")) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(path)
        path64 = _b64(normalized)
        script = f"""
set -u
path=$(printf '%s' {shlex.quote(path64)} | base64 -d)
remote_type=$(stat -Lc '%F' -- "$path" 2>/dev/null || true)
exists=no
if [ -e "$path" ] || [ -L "$path" ]; then exists=yes; fi
resolved=$(readlink -f -- "$path" 2>/dev/null || printf '%s' "$path")
if [ "$remote_type" != directory ]; then
  printf '__PATH_ERROR__\\t%s\\t%s\\t%s\\t%s\\n' \
    "$(printf '%s' "$path" | base64 -w0)" \
    "$(printf '%s' "$resolved" | base64 -w0)" \
    "$exists" "${{remote_type:-unknown}}"
  exit 44
fi
mount=$(findmnt -T "$path" -n -o TARGET 2>/dev/null || true)
filesystem=$(findmnt -T "$path" -n -o FSTYPE 2>/dev/null || true)
device=$(findmnt -T "$path" -n -o SOURCE 2>/dev/null || true)
printf '__DIR__\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \
  "$(stat -Lc '%a' -- "$path")" \
  "$(stat -Lc '%U:%G' -- "$path")" \
  "$(printf '%s' "$resolved" | base64 -w0)" \
  "$(printf '%s' "$mount" | base64 -w0)" \
  "$(printf '%s' "$filesystem" | base64 -w0)" \
  "$(printf '%s' "$device" | base64 -w0)"
while IFS= read -r -d '' item; do
  name64=$(basename -- "$item" | base64 -w0)
  item64=$(printf '%s' "$item" | base64 -w0)
  if [ -L "$item" ]; then kind=link; elif [ -d "$item" ]; then kind=directory; elif [ -f "$item" ]; then kind=file; else kind=other; fi
  printf '__ITEM__\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \
    "$name64" "$item64" "$kind" \
    "$(stat -c '%s' -- "$item" 2>/dev/null || printf 0)" \
    "$(stat -c '%A' -- "$item" 2>/dev/null || printf '?')" \
    "$(stat -c '%a' -- "$item" 2>/dev/null || printf '?')" \
    "$(stat -c '%U' -- "$item" 2>/dev/null || printf '?')" \
    "$(stat -c '%G' -- "$item" 2>/dev/null || printf '?')" \
    "$(stat -c '%Y' -- "$item" 2>/dev/null || printf 0)"
done < <(find "$path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
""".strip()
        code, output = _run_remote_bash(server, script, timeout=60)
        if code != 0:
            raise _directory_error(output, normalized)

        entries: list[dict[str, Any]] = []
        directory_meta: dict[str, Any] = {}
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 7 and parts[0] == "__DIR__":
                try:
                    directory_meta = {
                        "mode": parts[1],
                        "owner": parts[2],
                        "resolved_path": _decode(parts[3]),
                        "mount_point": _decode(parts[4]),
                        "filesystem": _decode(parts[5]),
                        "device": _decode(parts[6]),
                    }
                except Exception:
                    directory_meta = {"mode": parts[1], "owner": parts[2]}
                continue
            if len(parts) != 10 or parts[0] != "__ITEM__":
                continue
            try:
                name = _decode(parts[1])
                item_path = _decode(parts[2])
            except Exception:
                continue
            try:
                size = int(parts[4] or 0)
            except ValueError:
                size = 0
            try:
                modified = int(float(parts[9] or 0))
            except ValueError:
                modified = 0
            entries.append(
                {
                    "name": name,
                    "path": item_path,
                    "kind": parts[3],
                    "size": size,
                    "permissions": parts[5],
                    "mode": parts[6],
                    "owner": parts[7],
                    "group": parts[8],
                    "modified_at": modified,
                }
            )
        entries.sort(key=lambda item: (item["kind"] != "directory", item["name"].lower()))
        return {
            "path": normalized,
            "parent": None if normalized == "/" else normalized.rsplit("/", 1)[0] or "/",
            "directory": directory_meta,
            "entries": entries,
            "checked_at": _utc_now(),
        }

    @app.get("/api/vps/servers/{server_id}/files/usage")
    def directory_usage(server_id: int, path: str = Query(default="/")) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(path)
        path64 = _b64(normalized)
        script = f"""
set -u
path=$(printf '%s' {shlex.quote(path64)} | base64 -d)
remote_type=$(stat -Lc '%F' -- "$path" 2>/dev/null || true)
exists=no
if [ -e "$path" ] || [ -L "$path" ]; then exists=yes; fi
resolved=$(readlink -f -- "$path" 2>/dev/null || printf '%s' "$path")
if [ "$remote_type" != directory ]; then
  printf '__PATH_ERROR__\\t%s\\t%s\\t%s\\t%s\\n' \
    "$(printf '%s' "$path" | base64 -w0)" \
    "$(printf '%s' "$resolved" | base64 -w0)" \
    "$exists" "${{remote_type:-unknown}}"
  exit 44
fi
if [ "$(id -u)" -eq 0 ]; then
  mode=root
elif sudo -n true >/dev/null 2>&1; then
  mode=sudo
else
  mode=user
fi
find "$path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | \
  xargs -0 -r -n1 -P3 bash -c '
    mode="$1"
    item="$2"
    [ -d "$item" ] || exit 0
    if command -v timeout >/dev/null 2>&1; then runner="timeout 60s"; else runner=""; fi
    if [ "$mode" = sudo ]; then
      output=$($runner sudo -n du -x -B1 -s -- "$item" 2>/dev/null)
      rc=$?
    else
      output=$($runner du -x -B1 -s -- "$item" 2>/dev/null)
      rc=$?
    fi
    if [ "$rc" -eq 124 ]; then status=timeout; bytes=0
    else
      bytes=$(printf "%s\\n" "$output" | cut -f1)
      case "$bytes" in ""|*[!0-9]*) status=unavailable; bytes=0 ;; *) status=ok ;; esac
    fi
    encoded=$(printf "%s" "$item" | base64 -w0)
    printf "%s\\t%s\\t%s\\n" "$encoded" "$bytes" "$status"
  ' _ "$mode"
""".strip()
        code, output = _run_remote_bash(server, script, timeout=180)
        if code != 0:
            raise _directory_error(output, normalized)

        usage: list[dict[str, Any]] = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            try:
                item_path = _decode(parts[0])
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
  .file-view-toggle .btn{border:0;border-radius:0;box-shadow:none;min-width:38px}.file-view-toggle .btn.active{background:var(--brand);color:#fff}
  .file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;padding:14px}.file-grid[hidden],.file-list-pane[hidden]{display:none!important}
  .file-tile{border:1px solid var(--line);border-radius:13px;background:#fff;padding:14px;min-width:0;transition:.15s ease;display:flex;flex-direction:column;gap:10px}.file-tile:hover{border-color:#b8c9c0;box-shadow:0 8px 24px rgba(18,50,40,.08);transform:translateY(-1px)}
  .file-tile-main{display:flex;gap:11px;align-items:flex-start;min-width:0}.file-tile.folder .file-tile-main{cursor:pointer}.file-tile-icon{width:44px;height:44px;flex:0 0 44px;border-radius:12px;background:#eef5f1;display:grid;place-items:center;font-size:20px}.file-tile.folder .file-tile-icon{background:#fff4cf}
  .file-tile-copy{min-width:0;flex:1}.file-tile-copy b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}.file-tile-size{font-size:11px;font-weight:800;margin-top:5px;color:var(--brand2)}.file-tile-meta{font-size:9px;color:var(--muted);line-height:1.45;margin-top:4px;word-break:break-word}.file-tile-actions{display:flex;gap:5px;flex-wrap:wrap;margin-top:auto;padding-top:4px;border-top:1px solid #eef2ef}
  .usage-loading{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:10px}.usage-loading:before{content:"";width:9px;height:9px;border:1.5px solid #b5c2bc;border-top-color:var(--brand2);border-radius:50%;animation:spin .7s linear infinite}.file-size-strong{font-weight:760;color:#33443c}
  @media(max-width:700px){.file-grid{grid-template-columns:repeat(2,minmax(0,1fr));padding:10px}.file-tile{padding:11px}.file-tile-icon{width:38px;height:38px;flex-basis:38px}}@media(max-width:480px){.file-grid{grid-template-columns:1fr}}
</style>
<script id="file-manager-enhancement-script">
(() => {
  const section=document.getElementById('section-files'); if(!section||section.dataset.enhancedFileManager==='1')return; section.dataset.enhancedFileManager='1';
  let entries=[],usage=new Map(),usageStatus=new Map(),browseToken=0,usageToken=0;
  let viewMode=localStorage.getItem('custom-github.file-view')||'list'; let sortMode=localStorage.getItem('custom-github.file-sort')||'name';
  const toolbar=section.querySelector('.toolbar');
  toolbar.insertAdjacentHTML('beforeend',`<select id="fileSort" class="select" title="Sort files"><option value="name">Sort: Name</option><option value="size">Sort: Size</option><option value="modified">Sort: Modified</option></select><button id="fileRecalculateBtn" class="btn" type="button">◴ Folder sizes</button><div class="file-view-toggle"><button id="fileListViewBtn" class="btn tiny" type="button" title="List view">☷</button><button id="fileTileViewBtn" class="btn tiny" type="button" title="Tile view">▦</button></div>`);
  const card=section.querySelector('.card'),count=document.getElementById('fileCount');
  const browseBadge=document.createElement('span');browseBadge.id='fileBrowseState';browseBadge.className='tag green';browseBadge.textContent='Filesystem verified';count.parentNode.insertBefore(browseBadge,count);
  const usageBadge=document.createElement('span');usageBadge.id='fileUsageState';usageBadge.className='tag';usageBadge.textContent='Folder sizes idle';count.parentNode.insertBefore(usageBadge,count);
  const tableWrap=card.querySelector('.tablewrap');tableWrap.id='fileListPane';tableWrap.classList.add('file-list-pane');const sizeHeader=tableWrap.querySelector('thead th:nth-child(2)');if(sizeHeader)sizeHeader.textContent='Disk usage';tableWrap.insertAdjacentHTML('afterend','<div id="fileTilePane" class="file-grid" hidden></div>');
  const itemSize=i=>i.kind!=='directory'?Number(i.size||0):(usage.has(i.path)?Number(usage.get(i.path)||0):-1);
  const sizeHtml=i=>i.kind!=='directory'?`<span class="file-size-strong">${fmtBytes(i.size)}</span>`:usage.has(i.path)?`<span class="file-size-strong">${fmtBytes(usage.get(i.path))}</span>`:usageStatus.get(i.path)==='timeout'?'<span class="sub">Timed out</span>':usageStatus.get(i.path)==='unavailable'?'<span class="sub">Unavailable</span>':'<span class="usage-loading">Calculating…</span>';
  function sortedEntries(){const list=[...entries];list.sort((a,b)=>{if(a.kind==='directory'&&b.kind!=='directory')return-1;if(a.kind!=='directory'&&b.kind==='directory')return 1;if(sortMode==='size')return itemSize(b)-itemSize(a)||a.name.localeCompare(b.name);if(sortMode==='modified')return Number(b.modified_at||0)-Number(a.modified_at||0)||a.name.localeCompare(b.name);return a.name.localeCompare(b.name,undefined,{numeric:true,sensitivity:'base'})});return list}
  function actions(i){const p=i.kind==='directory'?`<button class="btn tiny" onclick='loadFiles(${JSON.stringify(i.path)})'>Open</button>`:i.kind==='file'?`<button class="btn tiny" onclick='editFile(${JSON.stringify(i.path)})'>Edit</button>`:'';return`${p}<button class="btn tiny" onclick='renamePath(${JSON.stringify(i.path)})'>Move</button><button class="btn tiny danger" onclick='trashPath(${JSON.stringify(i.path)})'>Trash</button>`}
  function render(){const list=sortedEntries(),rows=document.getElementById('fileRows'),tiles=document.getElementById('fileTilePane');rows.innerHTML=list.length?list.map(i=>`<tr><td><div class="filename"><span class="fileico ${i.kind==='directory'?'folder':''}">${i.kind==='directory'?'▰':i.kind==='link'?'↗':'▤'}</span><b title="${esc(i.path)}">${esc(i.name)}</b></div></td><td>${sizeHtml(i)}</td><td><span class="mono">${esc(i.permissions)}</span> <span class="tag">${esc(i.mode)}</span></td><td>${esc(i.owner)}:${esc(i.group)}</td><td>${fmtTime(i.modified_at)}</td><td><div class="actions">${actions(i)}</div></td></tr>`).join(''):'<tr><td colspan="6"><div class="empty">This directory is empty.</div></td></tr>';tiles.innerHTML=list.length?list.map(i=>`<article class="file-tile ${i.kind==='directory'?'folder':''}" title="${esc(i.path)}"><div class="file-tile-main" ${i.kind==='directory'?`ondblclick='loadFiles(${JSON.stringify(i.path)})'`:''}><div class="file-tile-icon">${i.kind==='directory'?'▰':i.kind==='link'?'↗':'▤'}</div><div class="file-tile-copy"><b>${esc(i.name)}</b><div class="file-tile-size">${sizeHtml(i)}</div><div class="file-tile-meta">${esc(i.owner)}:${esc(i.group)} · ${esc(i.permissions)}<br>${fmtTime(i.modified_at)}</div></div></div><div class="file-tile-actions">${actions(i)}</div></article>`).join(''):'<div class="empty" style="grid-column:1/-1">This directory is empty.</div>';}
  function setView(mode){viewMode=mode==='tile'?'tile':'list';localStorage.setItem('custom-github.file-view',viewMode);document.getElementById('fileListPane').hidden=viewMode!=='list';document.getElementById('fileTilePane').hidden=viewMode!=='tile';document.getElementById('fileListViewBtn').classList.toggle('active',viewMode==='list');document.getElementById('fileTileViewBtn').classList.toggle('active',viewMode==='tile')}
  async function loadUsage(path,force=false){const token=++usageToken;usageBadge.className='tag amber';usageBadge.innerHTML='<span class="usage-loading">Calculating folder sizes</span>';const button=document.getElementById('fileRecalculateBtn');button.disabled=true;button.textContent='◴ Calculating…';try{const data=await api(`/api/vps/servers/${serverId}/files/usage?path=${encodeURIComponent(path)}${force?'&refresh=1':''}`);if(token!==usageToken||path!==currentPath)return;usage=new Map();usageStatus=new Map();for(const i of data.usage||[]){usageStatus.set(i.path,i.status);if(i.status==='ok')usage.set(i.path,Number(i.bytes||0))}usageBadge.className='tag green';usageBadge.textContent=`${data.folders} folder${data.folders===1?'':'s'} · ${fmtBytes(data.bytes)} total`;render()}catch(err){if(token!==usageToken)return;usageBadge.className='tag amber';usageBadge.textContent='Folder sizes unavailable';toast('Folder size scan failed',err.message,'warning')}finally{if(token===usageToken){button.disabled=false;button.textContent='◴ Folder sizes'}}}
  async function enhancedLoadFiles(path='/'){const token=++browseToken;const requested=String(path||'/');browseBadge.className='tag amber';browseBadge.textContent=`Opening ${requested}`;try{const data=await api(`/api/vps/servers/${serverId}/files/browse?path=${encodeURIComponent(requested)}`);if(token!==browseToken)return;currentPath=data.path;entries=data.entries||[];usage=new Map();usageStatus=new Map();document.getElementById('filePath').value=currentPath;document.getElementById('fileUpBtn').disabled=currentPath==='/';document.getElementById('fileCount').textContent=`${entries.length} items`;const d=data.directory||{};document.getElementById('fileDirMeta').textContent=`${d.owner||''} · mode ${d.mode||'—'} · ${d.filesystem||'filesystem'} ${d.mount_point?`· mounted at ${d.mount_point}`:''} · folder sizes are allocated disk usage`;browseBadge.className='tag green';browseBadge.textContent=d.resolved_path&&d.resolved_path!==currentPath?`Resolved ${d.resolved_path}`:'Filesystem verified';render();setView(viewMode);void loadUsage(currentPath)}catch(err){if(token!==browseToken)return;browseBadge.className='tag red';browseBadge.textContent='Open failed';toast(`Unable to open ${requested}`,err.message,'error',7000);if(!entries.length){document.getElementById('fileRows').innerHTML=`<tr><td colspan="6"><div class="errorbox">${esc(err.message)}</div></td></tr>`;document.getElementById('fileTilePane').innerHTML=`<div class="errorbox" style="grid-column:1/-1">${esc(err.message)}</div>`}}}
  loadFiles=enhancedLoadFiles;document.getElementById('fileListViewBtn').onclick=()=>setView('list');document.getElementById('fileTileViewBtn').onclick=()=>setView('tile');document.getElementById('fileSort').value=sortMode;document.getElementById('fileSort').onchange=e=>{sortMode=e.target.value;localStorage.setItem('custom-github.file-sort',sortMode);render()};document.getElementById('fileRecalculateBtn').onclick=()=>void loadUsage(currentPath,true);setView(viewMode);
})();
</script>
"""


__all__ = ["FILE_MANAGER_ENHANCEMENT", "install_file_manager_enhancements_routes"]
