/* HIDEN · SEC4DATA — investigation workspace */
const $ = s => document.querySelector(s);
const TYPE_COLOR = {
  domain:"#00E5FF", subdomain:"#56c7d6", ip:"#7ee0c0", lookalike:"#ff3b5c",
  certificate:"#b388ff", asn:"#ffb020", org:"#ffd166", cve:"#ff7b54", ioc:"#ff5e7e",
  source:"#9ad0ff", case_note:"#8fb3c9", document:"#c0c9d4", email_domain:"#56c7d6"
};
const SEV_BADGE = {info:"b-info",low:"b-ok",medium:"b-warn",high:"b-alert",critical:"b-alert"};
const TYPE_LABEL = {domain:"Domain",subdomain:"Subdomain",ip:"IP",lookalike:"Lookalike",
  certificate:"Certificate",asn:"ASN",org:"Organization",cve:"CVE",ioc:"IOC",
  source:"Source/Profile",case_note:"Note",document:"Document",email_domain:"Email"};

let STATE = { invId:null, data:null, selected:null, sim:null, map:null, mapLayer:null, markers:{} };

/* ---------- utils ---------- */
setInterval(()=>{ $("#clock").textContent = new Date().toUTCString().slice(17,25)+" UTC"; },1000);
function esc(s){return (s==null?"":String(s)).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function toast(msg,err){const t=$("#toast");t.textContent=msg;t.className="toast show"+(err?" err":"");setTimeout(()=>t.className="toast",2600);}
async function api(path,method,body){
  const r=await fetch(path,{method:method||"GET",headers:{"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
  if(!r.ok){let d={};try{d=await r.json();}catch(e){} throw new Error(d.detail||("Error "+r.status));}
  return r.json();
}

/* ---------- meta ---------- */
api("/api/meta").then(m=>{ $("#ver").textContent = "v"+m.version; }).catch(()=>{});

/* ---------- investigations ---------- */
async function loadList(){
  const list = await api("/api/investigations");
  $("#invlist").innerHTML = list.length ? list.map(i=>`
    <div class="invitem ${i.id===STATE.invId?'active':''}" data-id="${i.id}">
      <div class="n">${esc(i.name)} ${i.authorized?'':'<span class="badge b-warn" style="font-size:8px">unauthorized</span>'}</div>
      <div class="m">${i.entities} ent · ${i.relations} rel · ${i.events} ev</div>
    </div>`).join("") : '<div class="note" style="padding:14px">No investigations yet.</div>';
  $("#invlist").querySelectorAll(".invitem").forEach(el=>el.onclick=()=>openInv(el.dataset.id));
}

$("#new-inv").onclick = ()=> showModal(`
  <span class="x" onclick="closeModal()">✕</span>
  <span class="eyebrow">New Operation</span><h2>Create Investigation</h2>
  <label class="fl">Operation name</label><input type="text" id="ni-name" placeholder="Operation Sentinel" />
  <label class="fl">Analyst</label><input type="text" id="ni-analyst" value="SEC4DATA" />
  <label class="fl">Scope / authorization basis (engagement, case no.)</label>
  <textarea id="ni-auth" rows="2" placeholder="Client XPTO engagement #2026-014 — written authorization"></textarea>
  <label class="chk" style="margin:12px 0"><input type="checkbox" id="ni-ok"> I confirm authorized, defensive use (owned assets or with explicit authorization).</label>
  <button class="btn" onclick="createInv()">Create</button>`);

window.createInv = async ()=>{
  const name=$("#ni-name").value.trim();
  if(!name) return toast("Enter a name.",true);
  if(!$("#ni-ok").checked) return toast("You must confirm authorized use.",true);
  const inv = await api("/api/investigations","POST",{name,analyst:$("#ni-analyst").value.trim()||"SEC4DATA",
    authorized:true,authorization_note:$("#ni-auth").value.trim()});
  closeModal(); await loadList(); openInv(inv.id);
  toast("Investigation created.");
};

async function openInv(id){
  STATE.invId=id;
  const meta = await api(`/api/investigations/${id}`);
  $("#empty").hidden=true; $("#grid").hidden=false; $("#wtool").hidden=false;
  $("#w-name").textContent = meta.name;
  $("#w-ref").textContent = `HDN/S4D/INTEL-${id.toUpperCase()} · ${meta.analyst}`;
  await loadList();
  await refresh();
  initMap(); setTimeout(()=>STATE.map&&STATE.map.invalidateSize(),80);
}

async function refresh(){
  STATE.data = await api(`/api/investigations/${STATE.invId}/graph`);
  renderGraph(); renderMap(); renderTimeline(); renderLegend();
}

/* ---------- collectors ---------- */
$("#op-run").onclick = async ()=>{
  const mod=$("#op-mod").value, target=$("#op-target").value.trim();
  if(!target && mod!=="cti") return toast("Enter a target.",true);
  const btn=$("#op-run"); btn.disabled=true; btn.textContent="…";
  try{
    let path=`/api/investigations/${STATE.invId}/collect/${mod}`, body={target};
    if(mod==="cti") body={ioc:target};
    await api(path,"POST",body);
    await refresh(); toast("Collection complete.");
  }catch(e){ toast(e.message,true); }
  finally{ btn.disabled=false; btn.textContent="Run"; }
};

$("#op-profile").onclick = ()=> showModal(`
  <span class="x" onclick="closeModal()">✕</span>
  <span class="eyebrow">Impersonation Detection</span><h2>Fake Profile</h2>
  <p class="note">Scores observable signals of a profile suspected of impersonating the brand/an executive. Defensive — analyzes the profile you provide.</p>
  <label class="fl">Handle</label><input type="text" id="pf-handle" placeholder="@suspect_handle" />
  <div class="row"><div><label class="fl">Age (days)</label><input type="number" id="pf-age"></div>
    <div><label class="fl">Followers</label><input type="number" id="pf-followers"></div></div>
  <div class="row"><div><label class="fl">Following</label><input type="number" id="pf-following"></div>
    <div><label class="fl">Posts</label><input type="number" id="pf-posts"></div></div>
  <div style="display:flex;flex-wrap:wrap;gap:12px;margin:12px 0">
    <label class="chk"><input type="checkbox" id="pf-nophoto"> no photo</label>
    <label class="chk"><input type="checkbox" id="pf-reused"> reused photo</label>
    <label class="chk"><input type="checkbox" id="pf-brand"> mimics brand</label>
    <label class="chk"><input type="checkbox" id="pf-person"> uses person's name</label>
    <label class="chk"><input type="checkbox" id="pf-promo"> promo only</label>
    <label class="chk"><input type="checkbox" id="pf-auto"> auto username</label>
    <label class="chk"><input type="checkbox" id="pf-verified"> verified</label>
  </div>
  <button class="btn" onclick="runProfile()">Assess Risk</button>`);

window.runProfile = async ()=>{
  const n=id=>{const v=$("#"+id).value.trim();return v===""?null:Number(v);};
  const c=id=>$("#"+id).checked||null;
  try{
    const r=await api(`/api/investigations/${STATE.invId}/collect/profile`,"POST",{
      handle:$("#pf-handle").value.trim()||"@profile",age_days:n("pf-age"),followers:n("pf-followers"),
      following:n("pf-following"),posts:n("pf-posts"),has_photo:$("#pf-nophoto").checked?false:null,
      photo_reused:c("pf-reused"),resembles_brand:c("pf-brand"),impersonates_person:c("pf-person"),
      promo_only:c("pf-promo"),auto_username:c("pf-auto"),verified:c("pf-verified")});
    closeModal(); await refresh();
    toast(`Risk ${r.score}/100 — ${r.verdict}`);
  }catch(e){ toast(e.message,true); }
};

$("#op-report").onclick = ()=>{
  if(!STATE.invId) return;
  toast("Generating forensic report…");
  window.open(`/api/investigations/${STATE.invId}/report.pdf`,"_blank");
};

/* ---------- HUMINT ---------- */
$("#open-humint").onclick = ()=>{
  if(!STATE.invId) return toast("Open an investigation first.",true);
  showModal(`
  <span class="x" onclick="closeModal()">✕</span>
  <span class="eyebrow">HUMINT · Case Management</span><h2>Source &amp; Notes</h2>
  <p class="note">Auditable record of information obtained from people <b>with consent/authorization</b>. Each source requires consent confirmation.</p>
  <label class="fl">Source codename</label><input type="text" id="hs-code" placeholder="BLUE-SOURCE" />
  <div class="row"><div><label class="fl">Reliability (A–F)</label>
    <select id="hs-rel"><option>A</option><option selected>B</option><option>C</option><option>D</option><option>E</option><option>F</option></select></div>
    <div><label class="fl">Context</label><input type="text" id="hs-ctx" placeholder="authorized interview"></div></div>
  <label class="chk" style="margin:12px 0"><input type="checkbox" id="hs-consent"> Source consent/authorization confirmed.</label>
  <button class="btn" onclick="addSource()">Register Source</button>
  <hr style="border-color:var(--line);margin:16px 0">
  <label class="fl">Note — source (codename)</label><input type="text" id="hn-src" placeholder="BLUE-SOURCE" />
  <label class="fl">Title</label><input type="text" id="hn-title" placeholder="Campaign origin" />
  <label class="fl">Content</label><textarea id="hn-content" rows="3"></textarea>
  <label class="fl">Credibility (1 confirmed – 6 n/a)</label><input type="text" id="hn-cred" value="3" />
  <button class="btn ghost" style="width:100%;margin-top:8px" onclick="addNote()">Add Note</button>`);
};
window.addSource = async ()=>{
  if(!$("#hs-consent").checked) return toast("You must confirm consent.",true);
  try{ await api(`/api/investigations/${STATE.invId}/humint/source`,"POST",{
    codename:$("#hs-code").value.trim(),reliability:$("#hs-rel").value,
    consent:true,context:$("#hs-ctx").value.trim()});
    await refresh(); toast("Source registered.");
  }catch(e){ toast(e.message,true); }
};
window.addNote = async ()=>{
  try{ await api(`/api/investigations/${STATE.invId}/humint/note`,"POST",{
    source_codename:$("#hn-src").value.trim(),title:$("#hn-title").value.trim(),
    content:$("#hn-content").value.trim(),credibility:$("#hn-cred").value.trim()});
    closeModal(); await refresh(); toast("Note added.");
  }catch(e){ toast(e.message,true); }
};

/* ---------- GRAPH (D3 force) ---------- */
function renderGraph(){
  const svg=d3.select("#graph"); svg.selectAll("*").remove();
  const el=$("#graph"), W=el.clientWidth, H=el.clientHeight;
  svg.attr("viewBox",`0 0 ${W} ${H}`);
  const nodes=STATE.data.nodes.map(n=>({...n})), idset=new Set(nodes.map(n=>n.id));
  const links=STATE.data.edges.filter(e=>idset.has(e.source)&&idset.has(e.target)).map(e=>({...e}));
  if(!nodes.length){ svg.append("text").attr("x",W/2).attr("y",H/2).attr("text-anchor","middle")
    .attr("fill","#62788a").attr("font-family","JetBrains Mono").text("No entities — run a collector."); return; }

  const g=svg.append("g");
  svg.call(d3.zoom().scaleExtent([.3,3]).on("zoom",ev=>g.attr("transform",ev.transform)));
  const link=g.append("g").selectAll("line").data(links).join("line")
    .attr("class",d=>"link"+(d.threat?" threat":"")).attr("stroke-width",d=>d.threat?1.6:1);
  const node=g.append("g").selectAll("g").data(nodes).join("g").attr("class","node")
    .call(d3.drag().on("start",dragStart).on("drag",dragged).on("end",dragEnd))
    .on("click",(ev,d)=>{ev.stopPropagation();selectEntity(d.id);});
  node.append("circle")
    .attr("r",d=>d.type==="domain"?13:(["lookalike","cve","ioc"].includes(d.type)?9:7))
    .attr("fill",d=>TYPE_COLOR[d.type]||"#00E5FF")
    .attr("stroke","#05080d").attr("stroke-width",2);
  node.append("text").attr("x",0).attr("y",d=>(d.type==="domain"?24:18)).attr("text-anchor","middle")
    .text(d=>d.label.length>22?d.label.slice(0,20)+"…":d.label);
  svg.on("click",()=>clearSelection());

  STATE.sim=d3.forceSimulation(nodes)
    .force("link",d3.forceLink(links).id(d=>d.id).distance(d=>d.threat?120:80))
    .force("charge",d3.forceManyBody().strength(-260))
    .force("center",d3.forceCenter(W/2,H/2))
    .force("collide",d3.forceCollide(26))
    .on("tick",()=>{
      link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
      node.attr("transform",d=>`translate(${d.x},${d.y})`);
    });
  function dragStart(ev,d){if(!ev.active)STATE.sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}
  function dragged(ev,d){d.fx=ev.x;d.fy=ev.y;}
  function dragEnd(ev,d){if(!ev.active)STATE.sim.alphaTarget(0);d.fx=null;d.fy=null;}
}
function renderLegend(){
  const types=[...new Set(STATE.data.nodes.map(n=>n.type))];
  $("#legend").innerHTML=types.map(t=>`<span><i style="background:${TYPE_COLOR[t]||'#00E5FF'}"></i>${esc(TYPE_LABEL[t]||t)}</span>`).join("");
}

/* ---------- MAP (Leaflet) ---------- */
function initMap(){
  if(STATE.map) return;
  STATE.map=L.map("map",{attributionControl:false,worldCopyJump:true}).setView([8.8,13.2],2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",{maxZoom:19}).addTo(STATE.map);
  STATE.mapLayer=L.layerGroup().addTo(STATE.map);
}
function renderMap(){
  if(!STATE.map) initMap();
  STATE.mapLayer.clearLayers(); STATE.markers={};
  const pts=STATE.data.geo||[]; const bounds=[];
  pts.forEach(p=>{
    const threat=["high","critical"].includes(p.severity);
    const m=L.circleMarker([p.lat,p.lon],{radius:threat?9:7,color:threat?"#ff3b5c":"#00E5FF",
      fillColor:threat?"#ff3b5c":"#00E5FF",fillOpacity:.55,weight:2})
      .bindPopup(`<b style="color:${threat?'#ff3b5c':'#00E5FF'}">${esc(p.label)}</b><br>${esc(p.city||'')} ${esc(p.country||'')}<br>${esc(p.isp||'')}<br>${esc(p.asn||'')}`)
      .on("click",()=>selectEntity(p.id));
    m.addTo(STATE.mapLayer); STATE.markers[p.id]=m; bounds.push([p.lat,p.lon]);
  });
  if(bounds.length) STATE.map.fitBounds(bounds,{padding:[36,36],maxZoom:6});
}

/* ---------- TIMELINE ---------- */
function renderTimeline(){
  const evs=STATE.data.events||[];
  $("#timeline").innerHTML = evs.length ? evs.map(e=>{
    const col=({info:"#62788a",low:"#29ffb0",medium:"#ffb020",high:"#ff3b5c",critical:"#ff3b5c"})[e.severity]||"#62788a";
    const tm=new Date(e.ts*1000).toLocaleString("en-GB",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"});
    return `<div class="tev" data-ents="${(e.entity_ids||[]).join(',')}">
      <div class="pin" style="background:${col};box-shadow:0 0 8px ${col}"></div>
      <div class="t">${esc(tm)}</div>
      <div class="c"><div class="mod">${esc(e.module)} · ${esc(e.action)}</div>${esc(e.summary)}</div></div>`;
  }).join("") : '<div class="note">No events.</div>';
  $("#timeline").querySelectorAll(".tev").forEach(el=>el.onclick=()=>{
    const ids=(el.dataset.ents||"").split(",").filter(Boolean);
    if(ids.length) selectEntity(ids[0]);
    $("#timeline").querySelectorAll(".tev").forEach(x=>x.classList.remove("sel"));
    el.classList.add("sel");
  });
}

/* ---------- SELECTION SYNC (graph ↔ map ↔ timeline ↔ inspector) ---------- */
function selectEntity(id){
  STATE.selected=id;
  const ent=STATE.data.nodes.find(n=>n.id===id); if(!ent) return;
  const neigh=new Set([id]);
  STATE.data.edges.forEach(e=>{ if(e.source===id)neigh.add(e.target); if(e.target===id)neigh.add(e.source); });
  d3.selectAll(".node").classed("dim",d=>!neigh.has(d.id));
  d3.selectAll(".link").classed("dim",d=>{const s=d.source.id||d.source,t=d.target.id||d.target;return !(s===id||t===id);});
  if(STATE.markers[id]){ STATE.map.setView(STATE.markers[id].getLatLng(),Math.max(STATE.map.getZoom(),5)); STATE.markers[id].openPopup(); }
  $("#timeline").querySelectorAll(".tev").forEach(el=>{
    el.classList.toggle("sel",(el.dataset.ents||"").split(",").includes(id)); });
  openInspector(ent);
}
function clearSelection(){
  STATE.selected=null;
  d3.selectAll(".node").classed("dim",false); d3.selectAll(".link").classed("dim",false);
  $("#inspector").classList.remove("open");
}
function openInspector(ent){
  const sev=ent.severity||"info";
  let attrs="";
  for(const[k,v] of Object.entries(ent.attrs||{})){
    if(v===null||v===undefined||v==="")continue;
    attrs+=`<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v)?v.join(", "):v)}</dd>`;
  }
  $("#inspector").innerHTML=`
    <span class="x" style="float:right;cursor:pointer;color:var(--muted)" onclick="clearSelection()">✕</span>
    <span class="eyebrow">${esc(TYPE_LABEL[ent.type]||ent.type)}</span>
    <h2>${esc(ent.label)}</h2>
    <span class="badge ${SEV_BADGE[sev]}">${esc(sev)}</span>
    <dl class="kv">${attrs||'<dt>—</dt><dd>no attributes</dd>'}</dl>`;
  $("#inspector").classList.add("open");
}
window.clearSelection=clearSelection;

/* ---------- modal ---------- */
function showModal(html){ $("#modal").innerHTML=html; $("#overlay").classList.add("open"); }
function closeModal(){ $("#overlay").classList.remove("open"); }
window.closeModal=closeModal;
$("#overlay").onclick=e=>{ if(e.target===$("#overlay")) closeModal(); };
window.addEventListener("resize",()=>{ if(STATE.data) renderGraph(); });

/* ---------- boot ---------- */
loadList();
