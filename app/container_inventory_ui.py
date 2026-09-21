from __future__ import annotations


CONTAINER_INVENTORY_DASHBOARD = r"""
<script id="container-inventory-dashboard">
(() => {
  const inventories = new Map();

  function ensureSection() {
    if (document.getElementById('containerInventorySection')) return;
    const manage = document.getElementById('manage');
    if (!manage) return;
    manage.insertAdjacentHTML('afterend', `
      <section class="section" id="containerInventorySection">
        <div class="section-title"><div><h2>Docker workload inventory</h2><div class="sub">Explains every running container by Compose stack and registered Custom GitHub project. “Review required” does not mean safe to delete.</div></div><div style="display:flex;gap:8px"><a class="btn" id="productionContractLink" href="#">Production Contract</a><button class="btn" id="inventoryRefreshBtn">↻ Analyze containers</button></div></div>
        <div class="grid">
          <div class="card c3 metric"><div class="label">Running on selected VPS</div><div class="value" id="invTotal">—</div><div class="caption">All running containers</div></div>
          <div class="card c3 metric"><div class="label">Registered projects</div><div class="value" id="invRegistered">—</div><div class="caption">Mapped to registered project stacks</div></div>
          <div class="card c3 metric"><div class="label">Compose stacks</div><div class="value" id="invStacks">—</div><div class="caption">Distinct running Compose projects</div></div>
          <div class="card c3 metric"><div class="label">Review required</div><div class="value" id="invReview">—</div><div class="caption">Unregistered stack or no Compose label</div></div>
        </div>
        <div class="grid" style="margin-top:14px">
          <article class="card c6"><div class="head"><div><h2>Running stacks</h2><div class="sub">A project can legitimately run several containers: app/API, database, cache, proxy and workers.</div></div></div><div class="pad"><div id="invStackRows" class="repo-list"><div class="empty">Analyzing Docker stacks…</div></div></div></article>
          <article class="card c6"><div class="head"><div><h2>Containers needing review</h2><div class="sub">Running containers that do not map to a registered Custom GitHub project.</div></div><a class="btn" id="invDockerLink" href="#">Open Docker</a></div><div class="pad"><div id="invReviewRows" class="repo-list"><div class="empty">Analyzing container ownership…</div></div></div></article>
        </div>
        <details class="card" style="margin-top:14px"><summary style="padding:15px 17px;cursor:pointer;font-size:12px;font-weight:800">Show every running container</summary><div class="pad"><div id="invContainerRows" class="repo-list"></div></div></details>
      </section>`);
    document.getElementById('inventoryRefreshBtn')?.addEventListener('click', loadInventories);
  }

  function roleText(roles) {
    const entries = Object.entries(roles || {});
    return entries.length ? entries.map(([k,v]) => `${k}: ${v}`).join(' · ') : 'No role classification';
  }

  function renderSelectedInventory() {
    ensureSection();
    const id = selectedId();
    const inv = inventories.get(Number(id));
    const contractLink=document.getElementById('productionContractLink'); if(contractLink && id) contractLink.href=`/vps/${id}/production-contract`;
    const set = (name, value) => { const el=document.getElementById(name); if(el) el.textContent=value; };
    if (!inv) {
      ['invTotal','invRegistered','invStacks','invReview'].forEach(x=>set(x,'—'));
      if (document.getElementById('invStackRows')) document.getElementById('invStackRows').innerHTML='<div class="empty">Container inventory unavailable for this VPS.</div>';
      return;
    }
    set('invTotal', inv.total_running);
    set('invRegistered', inv.registered_project_running);
    set('invStacks', inv.compose_stack_count);
    set('invReview', inv.review_required_running);
    const dockerLink=document.getElementById('invDockerLink'); if(dockerLink) dockerLink.href=`/vps/${id}?section=docker`;

    const stackRows=document.getElementById('invStackRows');
    stackRows.innerHTML=inv.stacks.length ? inv.stacks.map(s=>`<div class="repo"><div><b>${esc(s.name)}</b><small>${esc(s.registered_project ? `Registered project: ${s.registered_project}` : 'Not mapped to a registered project')} · ${esc(roleText(s.roles))}</small></div><span class="tag ${s.review_required?'red':'green'}">${s.container_count} container${s.container_count===1?'':'s'}</span></div>`).join('') : '<div class="empty">No running containers.</div>';

    const review=inv.containers.filter(c=>c.relation!=='registered-project');
    const reviewRows=document.getElementById('invReviewRows');
    reviewRows.innerHTML=review.length ? review.map(c=>`<div class="repo"><div><b>${esc(c.name)}</b><small>${esc(c.compose_project || 'No Compose project')} · ${esc(c.role)} · ${esc(c.image)}</small></div><span class="tag red">${esc(c.relation==='unmanaged'?'UNMANAGED':'UNREGISTERED STACK')}</span></div>`).join('') : '<div class="empty">Every running container maps to a registered project stack.</div>';

    const allRows=document.getElementById('invContainerRows');
    allRows.innerHTML=inv.containers.length ? inv.containers.map(c=>`<div class="repo"><div><b>${esc(c.name)}</b><small>${esc(c.compose_project || 'No Compose project')} / ${esc(c.compose_service || 'no service label')} · ${esc(c.role)} · ${esc(c.image)}</small></div><span class="tag ${c.relation==='registered-project'?'green':c.relation==='unmanaged'?'red':''}">${esc(c.registered_project || c.relation)}</span></div>`).join('') : '<div class="empty">No running containers.</div>';
  }

  function updateTopMetric() {
    const values=[...inventories.values()];
    if (!values.length) return;
    const total=values.reduce((n,x)=>n+Number(x.total_running||0),0);
    const registered=values.reduce((n,x)=>n+Number(x.registered_project_running||0),0);
    const review=values.reduce((n,x)=>n+Number(x.review_required_running||0),0);
    const count=document.getElementById('containerCount');
    if (count) {
      count.textContent=total;
      const card=count.closest('.metric');
      const label=card?.querySelector('.label'); const caption=card?.querySelector('.caption');
      if(label) label.textContent='All running containers';
      if(caption) caption.textContent=`${registered} mapped to registered projects · ${review} need review`;
    }
  }

  async function loadInventories() {
    ensureSection();
    const button=document.getElementById('inventoryRefreshBtn');
    if(button){button.disabled=true;button.textContent='Analyzing…';}
    try {
      const servers=(typeof S!=='undefined' && S.servers)||[];
      await Promise.all(servers.map(async s=>{
        try { inventories.set(Number(s.id), await api(`/api/vps/servers/${s.id}/docker/inventory`)); }
        catch (_) { inventories.delete(Number(s.id)); }
      }));
      updateTopMetric(); renderSelectedInventory();
    } finally {
      if(button){button.disabled=false;button.textContent='↻ Analyze containers';}
    }
  }

  ensureSection();
  document.getElementById('serverSelect')?.addEventListener('change',()=>setTimeout(renderSelectedInventory,0));
  window.setTimeout(loadInventories, 500);
  window.setInterval(loadInventories, 30000);
})();
</script>
"""


__all__ = ["CONTAINER_INVENTORY_DASHBOARD"]
