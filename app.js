/* pq-bench-rpi5 dashboard — pure client-side, reads a merged.json produced by
 * analyze/merge.py. No backend.
 *
 * Views (stage-6): TLS migration phases (Pi + Mac side by side), the full
 * three-stack handshake matrix, cross-implementation primitive comparison with
 * always-visible acceleration context, the original security-level charts
 * (preserved), and a deliberate-absences panel. All runs are SHOWN and
 * labelled — baseline-grade vs cross-platform-reference is a labelling
 * distinction, never a visibility one. */

const LEVEL_COLORS = { 1:"#3bd67a", 2:"#46c0c0", 3:"#3a7bff", 5:"#b06bff", 0:"#888" };
const BASE_COLOR = "#e0533d", PQ_COLOR = "#3a7bff";
const PHASE_COLORS = { baseline:"#e0533d", phase0:"#3bd67a", phase2:"#b06bff" };
const IMPL_COLORS = { liboqs:"#3a7bff", "aws-lc-rs":"#2fbfa7",
                      rustcrypto:"#f28c3b", openssl:"#e0533d" };
const IMPL_ORDER = ["liboqs", "aws-lc-rs", "rustcrypto", "openssl"];
const TLS_IMPLS = ["openssl-native", "oqs-provider", "rustls-awslc"];

let MERGED = null, CHARTS = [];
const UI = { phaseFamily:"X25519MLKEM768", phaseImpl:"openssl-native",
             tlsRun:null, lvlRun:null, lvlImpl:"liboqs",
             xKemOp:"keygen", xSigOp:"sign" };

const $ = (id) => document.getElementById(id);
const nsToMs = (ns) => (ns || 0) / 1e6;
const norm = (s) => (s||"").toLowerCase().replace(/[^a-z0-9]/g, "");

/* compact ms label: more decimals for small values, fewer for large. Guards its
 * input — Chart.js may hand a value-label formatter a parsed {x,y} point or a
 * non-number. */
const fmtMs = (v) => {
  const ms = typeof v === "number" ? v
           : (v && typeof v === "object") ? (typeof v.y === "number" ? v.y : NaN)
           : Number(v);
  if (!Number.isFinite(ms)) return "";
  return ms>=100?ms.toFixed(0):ms>=10?ms.toFixed(1):ms>=1?ms.toFixed(2):ms.toFixed(3);
};
/* human tick labels for log axes spanning µs..s (values are in ms) */
const logTick = (v) => {
  const l = Math.log10(v);
  if (Math.abs(l - Math.round(l)) > 1e-9) return "";
  if (v < 1) return (v*1000) + " µs";
  if (v < 1000) return v + " ms";
  return (v/1000) + " s";
};
const logScale = (label) => ({ type:"logarithmic",
  title:{display:true,text:label+" (log)",color:"#9aa3b2"},
  ticks:{color:"#9aa3b2", callback:logTick, autoSkip:false} });
const linScale = (label) => ({ type:"linear",
  title:{display:true,text:label,color:"#9aa3b2"}, ticks:{color:"#9aa3b2"} });

/* diagonal-hatch canvas pattern (secondary cue for portable code paths) */
const PATTERNS = {};
function hatch(color, alpha=1) {
  const key = color + alpha;
  if (PATTERNS[key]) return PATTERNS[key];
  const c = document.createElement("canvas"); c.width = c.height = 8;
  const x = c.getContext("2d");
  x.globalAlpha = alpha;
  x.fillStyle = color; x.fillRect(0,0,8,8);
  x.globalAlpha = 1;
  x.strokeStyle = "rgba(15,17,21,0.65)"; x.lineWidth = 2;
  x.beginPath(); x.moveTo(-2,6); x.lineTo(6,-2); x.moveTo(2,10); x.lineTo(10,2); x.stroke();
  return PATTERNS[key] = x.createPattern(c, "repeat");
}
function withAlpha(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n>>16},${(n>>8)&255},${n&255},${a})`;
}

/* Inline plugin: value labels above bars. formatter(value, index, dsIndex). */
const valueLabels = {
  id: "valueLabels",
  afterDatasetsDraw(chart) {
    /* NB: formatters live on chart.$pqb, NOT in options — Chart.js v4 resolves
     * plugin options through a scriptable-options proxy that INVOKES functions
     * while resolving them (formatter->valueOf recursion). */
    const opt = chart.$pqb || {};
    if (!opt.formatter) return;
    const ctx = chart.ctx;
    ctx.save();
    ctx.fillStyle = "#e6e8ee"; ctx.font = "10px sans-serif";
    ctx.textAlign = "center"; ctx.textBaseline = "bottom";
    chart.data.datasets.forEach((ds, di) => {
      const meta = chart.getDatasetMeta(di);
      if (meta.hidden) return;
      meta.data.forEach((el, i) => {
        const v = ds.data[i];
        if (v == null) return;
        /* opt.stagger: alternate label heights per dataset so side-by-side
         * near-equal bars (Pi vs Mac) don't overprint each other */
        const dy = opt.stagger ? (di % 2 ? 14 : 3) : 3;
        ctx.fillText(opt.formatter(v, i, di), el.x, el.y - dy);
      });
    });
    ctx.restore();
  }
};
/* Inline plugin: ◆ markers inside bars (the primitive-sum-of-medians overlay).
 * options.plugins.sumMarkers.values[dsIndex][i] = value in axis units or null. */
const sumMarkers = {
  id: "sumMarkers",
  afterDatasetsDraw(chart) {
    const opt = chart.$pqb || {};
    if (!opt.sums) return;
    const y = chart.scales.y, ctx = chart.ctx;
    ctx.save();
    chart.data.datasets.forEach((ds, di) => {
      const meta = chart.getDatasetMeta(di);
      if (meta.hidden) return;
      meta.data.forEach((el, i) => {
        const v = (opt.sums[di]||[])[i];
        if (v == null) return;
        const py = y.getPixelForValue(v);
        ctx.fillStyle = "#ffe066";
        ctx.beginPath();
        ctx.moveTo(el.x, py-5); ctx.lineTo(el.x+5, py);
        ctx.lineTo(el.x, py+5); ctx.lineTo(el.x-5, py);
        ctx.closePath(); ctx.fill();
      });
    });
    ctx.restore();
  }
};
if (window.Chart) { Chart.register(valueLabels); Chart.register(sumMarkers); }

async function boot() {
  $("fileInput").addEventListener("change", onFile);
  $("tlsLog").addEventListener("change", render);
  $("xLog").addEventListener("change", render);
  $("lvlLog").addEventListener("change", render);
  try {
    const r = await fetch("data/merged.json", { cache: "no-store" });
    if (r.ok) { MERGED = await r.json(); afterLoad(); }
    else showEmpty("No data/merged.json yet. Run a benchmark, then: " +
                   "<code>python3 analyze/merge.py</code> — or load a results file above.");
  } catch (e) {
    showEmpty("Could not auto-load data/merged.json (open via a local server or use the file picker).");
  }
}

function onFile(ev) {
  const f = ev.target.files[0]; if (!f) return;
  const rd = new FileReader();
  rd.onload = () => {
    const d = JSON.parse(rd.result);
    MERGED = d.merged_schema ? d : wrapSingle(d);
    afterLoad();
  };
  rd.readAsText(f);
}

/* wrap a single results JSON into the merged shape so the picker works too */
function wrapSingle(d) {
  const rid = `${(d.host||{}).hostname}@${d.generated_utc}`;
  const meta = { run_id: rid, hostname:(d.host||{}).hostname, cpu_brand:(d.host||{}).cpu_brand,
                 is_rpi:(d.host||{}).is_rpi, is_baseline_grade:d.is_baseline_grade };
  const kem=[], sig=[], tls=[], kem_absent=[], sig_absent=[], tls_absent=[];
  const prim = (rows, out, absent) => (rows||[]).forEach(k => {
    if (!k.enabled) { absent.push({...meta, alg:k.alg,
        implementation:k.implementation||k.backend, reason:k.reason||""}); return; }
    Object.entries(k.operations||{}).forEach(([op,st]) =>
      out.push({...meta, alg:k.alg, implementation:k.implementation||k.backend,
                classical:!!k.classical, nist_level:k.claimed_nist_level,
                operation:op, median_ns:st.median, sizes:k.sizes,
                acceleration:k.acceleration}));
  });
  prim(d.kem, kem, kem_absent); prim(d.sig, sig, sig_absent);
  ((d.tls||{}).matrix||[]).forEach(c => {
    const sig_alg = c.sig_alg || ((c.label||"").split("+")[1]||"");
    if (!c.enabled) { tls_absent.push({...meta, label:c.label, group:c.group,
        sig_alg, phase:c.phase||"", implementation:c.implementation||"oqs-provider",
        unstable_features:!!c.unstable_features, reason:c.reason||""}); return; }
    tls.push({...meta, label:c.label, group:c.group, sig_alg,
      phase:c.phase, implementation:c.implementation||"oqs-provider",
      unstable_features:!!c.unstable_features,
      is_baseline_pair:c.label===((d.tls||{}).baseline||{}).label,
      handshakes_per_sec:c.handshakes_per_sec, median_ns:(c.handshake_latency_ns||{}).median,
      primitive_sum_of_medians_ns:((c.handshake_primitive_sum||{}).sum_of_medians_ns),
      bytes_total:(c.bytes_on_wire||{}).total, client_hello_bytes:c.client_hello_bytes,
      client_hello_fragmented:c.client_hello_fragmented});
  });
  return { merged_schema:"single", n_runs:1,
           runs:[{run_id:rid, host:d.host, is_baseline_grade:d.is_baseline_grade,
                  baseline_grade_reasons:d.baseline_grade_reasons||[], toolchain:d.toolchain,
                  cpu_features:d.cpu_features, run:d.run,
                  thermal_summary:{temp_c:(d.thermal_trace||{}).temp_c,
                                   throttling_detected:(d.thermal_trace||{}).throttling_detected},
                  generated_utc:d.generated_utc}],
           kem, sig, tls, kem_absent, sig_absent, tls_absent };
}

/* short platform tag for legends: "Pi 5" / "M3" style, from the host brand */
function runTag(r) {
  const b = ((MERGED.runs.find(x=>x.run_id===r.run_id)||r).host||{}).cpu_brand ||
            r.cpu_brand || r.hostname || "?";
  if (/raspberry/i.test(b)) return "Pi 5";
  const m = b.match(/Apple (M\d+(?: \w+)?)/i);
  if (m) return m[1];
  const clean = b.replace(/\((R|TM)\)/gi, "");
  const x86 = clean.match(/(Ultra \d+|i\d-\w+|Ryzen \d( \w+)?)/i);
  return x86 ? x86[1] : clean.split(/\s+/).slice(0,2).join(" ");
}
function runsOrdered() {  // baseline-grade first
  return MERGED.runs.slice().sort((a,b)=>(b.is_baseline_grade?1:0)-(a.is_baseline_grade?1:0));
}

function afterLoad() {
  const runs = runsOrdered();
  UI.tlsRun = UI.tlsRun || runs[0].run_id;
  UI.lvlRun = UI.lvlRun || runs[0].run_id;
  renderRunCards();
  buildPills("phaseFamily", ["X25519MLKEM768","MLKEM768","MLKEM1024"], "phaseFamily");
  buildPills("phaseImpl", TLS_IMPLS, "phaseImpl");
  buildPills("tlsRun", runs.map(r=>({v:r.run_id, t:runTag({run_id:r.run_id})})), "tlsRun");
  buildPills("lvlRun", runs.map(r=>({v:r.run_id, t:runTag({run_id:r.run_id})})), "lvlRun");
  buildPills("lvlImpl", IMPL_ORDER.filter(i=>i!=="openssl"), "lvlImpl");
  buildPills("xKemOp", ["keygen","encaps","decaps"], "xKemOp");
  buildPills("xSigOp", ["keygen","sign","verify"], "xSigOp");
  render();
}

function buildPills(elId, items, key) {
  const el = $(elId); el.innerHTML = "";
  items.forEach(it => {
    const v = typeof it === "string" ? it : it.v;
    const t = typeof it === "string" ? it : it.t;
    const s = document.createElement("span");
    s.className = "pill" + (UI[key] === v ? " on" : "");
    s.textContent = t;
    s.onclick = () => { UI[key] = v;
      el.querySelectorAll(".pill").forEach(p=>p.classList.remove("on"));
      s.classList.add("on"); render(); };
    el.appendChild(s);
  });
}

function render() {
  if (!MERGED) return;
  CHARTS.forEach(c => c.destroy()); CHARTS = [];
  phasePanel();
  tlsMatrix();
  clientHello();
  crossImpl("ximpl_kem", MERGED.kem, UI.xKemOp, "KEM — " + UI.xKemOp);
  crossImpl("ximpl_sig", MERGED.sig, UI.xSigOp, "Signatures — " + UI.xSigOp);
  accelTable();
  levelCharts();
  absencesPanel();
}

/* ---- run cards -------------------------------------------------------------- */
function renderRunCards() {
  const el = $("run-cards"); el.innerHTML = "";
  runsOrdered().forEach(r => {
    const h = r.host||{}, t = r.toolchain||{}, th = r.thermal_summary||{};
    const good = r.is_baseline_grade;
    const card = document.createElement("div");
    card.className = "run-card " + (good ? "good" : "ref");
    const reasons = (r.baseline_grade_reasons||[]).map(x=>`<li>${x}</li>`).join("");
    card.innerHTML =
      `<span class="tag">${good ? "✅ baseline-grade (RPi5 reference)"
                                : "⚠ cross-platform reference — not baseline-grade"}</span><br>` +
      `<b>${h.cpu_brand||"?"}</b> · ${h.os_pretty||h.os||"?"} · ${r.generated_utc||""}` +
      (good ? "" : `<details><summary>why it doesn't meet the reference bar</summary><ul>${reasons}</ul></details>`) +
      `<div class="chips">` +
      `<span class="chip">flags <b>${t.cflags_target||"?"}</b></span>` +
      `<span class="chip">openssl <b>${t.openssl||"?"}</b></span>` +
      `<span class="chip">liboqs <b>${(t.liboqs_commit||"").slice(0,8)}</b></span>` +
      `<span class="chip">rust <b>${(t.rust&&t.rust.available)?"✓":"—"}</b></span>` +
      `<span class="chip">temp <b>${th.temp_c?th.temp_c.max+"°C max":"n/a"}</b>${th.throttling_detected?" ⚠":""}</span>` +
      `</div>`;
    el.appendChild(card);
  });
}

/* ---- TLS phase panel (Pi + Mac side by side) -------------------------------- */
function tlsCell(rows, rid, impl, group, sig) {
  return rows.find(r => r.run_id===rid && r.implementation===impl &&
                        norm(r.group)===norm(group) && norm(r.sig_alg)===norm(sig));
}
function phaseSteps(family) {
  return [
    { name:"baseline", group:"X25519", sig:"ed25519", phase:"baseline" },
    { name:"phase 0", group:family, sig:"ed25519", phase:"phase0" },
    { name:"phase 2 · 44", group:family, sig:"ML-DSA-44", phase:"phase2" },
    { name:"phase 2 · 65", group:family, sig:"ML-DSA-65", phase:"phase2" },
    { name:"phase 2 · 87", group:family, sig:"ML-DSA-87", phase:"phase2" },
  ];
}
function phasePanel() {
  const steps = phaseSteps(UI.phaseFamily);
  const runs = runsOrdered();
  const latDs = [], byteDs = [], sums = [];
  runs.forEach((run, ri) => {
    const tag = runTag({run_id:run.run_id});
    const cells = steps.map(s => tlsCell(MERGED.tls, run.run_id, UI.phaseImpl, s.group, s.sig));
    const base = cells[0];
    const colors = steps.map((s,i) => {
      const c = PHASE_COLORS[s.phase];
      return ri === 0 ? c : withAlpha(c, 0.45);
    });
    latDs.push({ label:tag, data:cells.map(c=>c?nsToMs(c.median_ns):null),
      backgroundColor:colors, borderColor:steps.map(s=>PHASE_COLORS[s.phase]),
      borderWidth:ri===0?0:1.5,
      _mult: cells.map(c => (c && base) ? c.median_ns/base.median_ns : null) });
    sums.push(cells.map(c => (c && c.primitive_sum_of_medians_ns)
                              ? nsToMs(c.primitive_sum_of_medians_ns) : null));
    byteDs.push({ label:tag, data:cells.map(c=>c?c.bytes_total:null),
      backgroundColor:colors, borderColor:steps.map(s=>PHASE_COLORS[s.phase]),
      borderWidth:ri===0?0:1.5,
      _mult: cells.map(c => (c && base) ? c.bytes_total/base.bytes_total : null) });
  });
  const labels = steps.map(s=>s.name);
  const multFmt = (dsArr) => (v,i,di) => {
    const m = ((dsArr[di]||{})._mult||[])[i];
    return m ? `${fmtMs(v)} ×${m.toFixed(2)}` : fmtMs(v);
  };
  const anyData = latDs.some(d => d.data.some(v => v != null));
  if (!anyData) {
    drawEmpty("phase_latency", `${UI.phaseImpl} has no cells for this family (see absences)`);
    drawEmpty("phase_bytes", "");
    return;
  }
  mkChart("phase_latency", { type:"bar",
    data:{ labels, datasets:latDs },
    options:{ responsive:true, plugins:{
      title:{display:true, text:`Handshake latency by phase — ${UI.phaseFamily} · ${UI.phaseImpl}`, color:"#e6e8ee"},
      legend:{labels:{color:"#9aa3b2"}},
      tooltip:{callbacks:{ label:(it)=>`${it.dataset.label}: ${fmtMs(it.raw)} ms`,
        afterLabel:(it)=>{ const s=(sums[it.datasetIndex]||[])[it.dataIndex];
          return s?`primitive sum-of-medians: ${fmtMs(s)} ms (derived)`:""; } }} },
    scales:{ x:{ticks:{color:"#9aa3b2"}}, y:linScale("median handshake latency (ms)") } }},
    { stagger:true, formatter: multFmt(latDs), sums });
  mkChart("phase_bytes", { type:"bar",
    data:{ labels, datasets:byteDs },
    options:{ responsive:true, plugins:{
      title:{display:true, text:`Bytes on the wire by phase — ${UI.phaseFamily} · ${UI.phaseImpl}`, color:"#e6e8ee"},
      legend:{labels:{color:"#9aa3b2"}},
      tooltip:{callbacks:{label:(it)=>`${it.dataset.label}: ${it.raw.toLocaleString()} B`}} },
    scales:{ x:{ticks:{color:"#9aa3b2"}}, y:linScale("bytes on the wire") } }},
    { stagger:true, formatter:(v,i,di)=>{ const m=((byteDs[di]||{})._mult||[])[i];
        return m?`${(v/1000).toFixed(1)}kB ×${m.toFixed(2)}`:`${(v/1000).toFixed(1)}kB`; } });
}

/* ---- TLS full matrix -------------------------------------------------------- */
function tlsMatrix() {
  const rows = MERGED.tls.filter(r => r.run_id === UI.tlsRun);
  if (!rows.length) return drawEmpty("tls_hs", "no TLS rows for this run");
  const implRank = (i)=>TLS_IMPLS.indexOf(i);
  const phaseRank = {baseline:0, phase0:1, phase2:2};
  const data = rows.slice().sort((a,b)=> implRank(a.implementation)-implRank(b.implementation)
      || (phaseRank[a.phase]??3)-(phaseRank[b.phase]??3)
      || (b.handshakes_per_sec||0)-(a.handshakes_per_sec||0));
  const labels = data.map(r=>`${r.implementation} · ${r.label}${r.unstable_features?" ᵁ":""}`);
  const log = $("tlsLog").checked;
  mkChart("tls_hs", { type:"bar",
    data:{ labels, datasets:[{ label:"handshakes/sec",
      data:data.map(r=>r.handshakes_per_sec),
      backgroundColor:data.map(r=>PHASE_COLORS[r.phase]||PQ_COLOR) }] },
    options:{ indexAxis:"y", responsive:true, maintainAspectRatio:false, plugins:{
      title:{display:true,text:`TLS 1.3 handshake throughput — ${runTag({run_id:UI.tlsRun})} (red=baseline, green=phase0, purple=phase2)`,color:"#e6e8ee"},
      legend:{display:false},
      tooltip:{callbacks:{afterLabel:(it)=>{ const r=data[it.dataIndex];
        return `${r.phase} · median ${fmtMs(nsToMs(r.median_ns))} ms` +
               (r.unstable_features?" · unstable cargo features":""); }}} },
    scales:{ x: log ? {...logScale("handshakes/sec"),
                       ticks:{color:"#9aa3b2",callback:(v)=>{const l=Math.log10(v);
                         return Math.abs(l-Math.round(l))<1e-9?v.toLocaleString():"";}}}
                    : linScale("handshakes/sec"),
             y:{ticks:{color:"#9aa3b2",font:{size:9.5}}} } }});
}

function clientHello() {
  const rows = MERGED.tls.filter(r => r.run_id === UI.tlsRun);
  if (!rows.length) return drawEmpty("tls_chello", "no TLS rows");
  const seen = new Set(); const data = [];
  rows.slice().sort((a,b)=>(b.client_hello_bytes||0)-(a.client_hello_bytes||0))
    .forEach(r => { const k = r.implementation+"|"+r.group;   // CH depends on group+stack, not sig
      if (!seen.has(k)) { seen.add(k); data.push(r); } });
  mkChart("tls_chello", { type:"bar",
    data:{ labels:data.map(r=>`${r.implementation} · ${r.group}`),
      datasets:[{ label:"ClientHello bytes",
        data:data.map(r=>r.client_hello_bytes),
        backgroundColor:data.map(r=>PHASE_COLORS[r.phase]||PQ_COLOR),
        borderColor:data.map(r=>r.client_hello_fragmented?"#ffa94d":"transparent"),
        borderWidth:data.map(r=>r.client_hello_fragmented?2:0) }] },
    options:{ indexAxis:"y", responsive:true, maintainAspectRatio:false, plugins:{
      title:{display:true,text:`ClientHello size — ${runTag({run_id:UI.tlsRun})} (orange border = exceeds ~1400B MSS → fragments)`,color:"#e6e8ee"},
      legend:{display:false},
      annotation:{ annotations:{ mss:{ type:"line", xMin:1400, xMax:1400,
        borderColor:"#d98b2b", borderWidth:1, borderDash:[4,4],
        label:{display:true,content:"~MSS 1400B",position:"start",backgroundColor:"#d98b2b",font:{size:9}} } } } },
    scales:{ x:linScale("bytes"), y:{ticks:{color:"#9aa3b2",font:{size:9.5}}} } }});
}

/* ---- cross-implementation primitives (Pi + Mac side by side) ---------------- */
function crossImpl(canvasId, rows, op, title) {
  const runs = runsOrdered();
  // algorithms measured by >=2 implementations (for this op)
  const byAlg = {};
  rows.forEach(r => { if (r.operation===op)
    (byAlg[r.alg] = byAlg[r.alg] || new Set()).add(r.implementation); });
  const algs = Object.keys(byAlg).filter(a => byAlg[a].size >= 2)
    .sort((a,b)=>a.localeCompare(b, undefined, {numeric:true}));
  if (!algs.length) return drawEmpty(canvasId, `${title}: no multi-implementation rows`);
  const log = $("xLog").checked;
  const datasets = [];
  IMPL_ORDER.forEach(impl => {
    runs.forEach((run, ri) => {
      const cells = algs.map(a => rows.find(r => r.run_id===run.run_id &&
        r.implementation===impl && r.alg===a && r.operation===op) || null);
      if (!cells.some(c=>c)) return;
      const alpha = ri===0 ? 1 : 0.45;
      datasets.push({
        label:`${impl} (${runTag({run_id:run.run_id})})`,
        data:cells.map(c=>c?nsToMs(c.median_ns):null),
        backgroundColor:cells.map(c=>{
          if (!c) return "transparent";
          const asm = /asm|native|internal/i.test(((c.acceleration||{}).arithmetic||{}).path||"");
          const col = IMPL_COLORS[impl]||PQ_COLOR;
          return asm ? (ri===0?col:withAlpha(col,alpha)) : hatch(col, alpha);
        }),
        borderColor:IMPL_COLORS[impl], borderWidth:ri===0?0:1.5,
        _cells:cells });
    });
  });
  mkChart(canvasId, { type:"bar",
    data:{ labels:algs, datasets },
    options:{ responsive:true, plugins:{
      title:{display:true,text:`${title} — median latency (independent implementations)`,color:"#e6e8ee"},
      legend:{labels:{color:"#9aa3b2", font:{size:10.5}}},
      tooltip:{callbacks:{
        label:(it)=>`${it.dataset.label}: ${fmtMs(it.raw)} ms`,
        afterLabel:(it)=>{
          const c = (it.dataset._cells||[])[it.dataIndex];
          if (!c || !c.acceleration) return "";
          const a = c.acceleration, ar = a.arithmetic||{}, sy = (a.symmetric||[])[0];
          return [`arithmetic: ${ar.path}${ar.detail?" — "+ar.detail:""}`,
                  sy?`symmetric: ${sy.primitive} via ${sy.source}${sy.hw_instructions?" (hw)":""}`:"",
                  `determined by: ${a.determined_by}`].filter(Boolean).join("\n");
        } }} },
    scales:{ x:{ticks:{color:"#9aa3b2",maxRotation:50,minRotation:35,font:{size:10.5}}},
             y: log ? logScale("median latency") : linScale("median latency (ms)") } }});
}

/* the always-visible acceleration table (authoritative; hatching is secondary) */
function accelTable() {
  const runs = runsOrdered();
  const fams = {};
  const famOf = (alg) => alg
    .replace(/^ML-KEM-\d+$/, "ML-KEM").replace(/^ML-DSA-\d+$/, "ML-DSA")
    .replace(/^SLH_DSA_PURE_(SHA2|SHAKE)_.*$/, "SLH-DSA-$1")
    .replace(/^SPHINCS\+-(SHA2|SHAKE)-.*$/, "SPHINCS+-$1")
    .replace(/^Falcon-\d+$/, "Falcon")
    .replace(/^FrodoKEM-\d+-(AES|SHAKE)$/, "FrodoKEM-$1")
    .replace(/^Classic-McEliece-.*$/, "Classic-McEliece");
  [...MERGED.kem, ...MERGED.sig].forEach(r => {
    if (!r.acceleration) return;
    const key = famOf(r.alg) + "|" + r.implementation;
    const f = fams[key] = fams[key] ||
      { fam:famOf(r.alg), impl:r.implementation, byRun:{} };
    f.byRun[r.run_id] = r.acceleration;
  });
  const implRank = (i)=>IMPL_ORDER.indexOf(i);
  const list = Object.values(fams).sort((a,b)=>
    a.fam.localeCompare(b.fam) || implRank(a.impl)-implRank(b.impl));
  const hwMark = (acc) => {
    const sy = ((acc||{}).symmetric||[])[0];
    if (!sy) return "—";
    return sy.hw_instructions ? "✓ hw" : (sy.hw_instructions===false ? "✗" : "?");
  };
  let html = `<table><tr><th>algorithm</th><th>implementation</th><th>arithmetic path</th>
    <th>symmetric path</th>${runs.map(r=>`<th>hw instr (${runTag({run_id:r.run_id})})</th>`).join("")}</tr>`;
  list.forEach(f => {
    const any = Object.values(f.byRun)[0] || {};
    const ar = any.arithmetic||{};
    const sy = (any.symmetric||[])[0];
    const asm = /asm|native|internal/i.test(ar.path||"");
    html += `<tr><td class="alg">${f.fam}</td><td>${f.impl}</td>` +
      `<td class="${asm?"asm":"portable"}">${ar.path||"?"}${ar.detail?` <span title="${ar.detail}">ⓘ</span>`:""}</td>` +
      `<td>${sy ? `${sy.primitive} — ${sy.source}` : "none"}</td>` +
      runs.map(r=>`<td>${hwMark(f.byRun[r.run_id])}</td>`).join("") + `</tr>`;
  });
  $("accel-table").innerHTML = html + "</table>";
}

/* ---- security-level charts (preserved from the original dashboard) ---------- */
function levelCharts() {
  // classical anchor rows come from the matching implementation family:
  // liboqs charts anchor on the openssl EVP baselines (the C stack), the Rust
  // and aws-lc-rs charts anchor on their own in-family classical rows.
  const anchorImpl = UI.lvlImpl === "liboqs" ? "openssl" : UI.lvlImpl;
  const filt = (rows) => rows.filter(r => r.run_id === UI.lvlRun &&
    (r.implementation === UI.lvlImpl || (r.classical && r.implementation === anchorImpl)));
  const kem = filt(MERGED.kem), sig = filt(MERGED.sig);
  const log = $("lvlLog").checked;
  barByLevel("kem_keygen", kem, "keygen", "KEM keygen — median latency", log);
  barByLevel("kem_encaps", kem, "encaps", "KEM encaps — median latency", log, "derive");
  barByLevel("kem_decaps", kem, "decaps", "KEM decaps — median latency", log, "derive");
  scatter("kem_scatter", kem, "encaps", "public_key", "KEM size vs speed (encaps)", "public key (B)");
  barByLevel("sig_sign", sig, "sign", "Signature sign — median latency", log);
  barByLevel("sig_verify", sig, "verify", "Signature verify — median latency", log);
  scatter("sig_scatter", sig, "sign", "signature", "Signature size vs speed (sign)", "signature (B)", true);
}

function baselineAnnotation(value, label) {
  if (value == null) return {};
  return { annotations: { base: {
    type:"line", yMin:value, yMax:value, borderColor:BASE_COLOR,
    borderWidth:2, borderDash:[6,4],
    label:{ display:true, content:label, position:"end",
            backgroundColor:BASE_COLOR, font:{size:10} } } } };
}

function barByLevel(canvasId, rows, op, title, logY, baselineOp = op) {
  const data = rows.filter(r => r.operation === op)
                   .sort((a,b)=>(a.nist_level||0)-(b.nist_level||0) || a.median_ns-b.median_ns);
  if (!data.length) return drawEmpty(canvasId, `${title}: no rows for this implementation`);
  /* Baseline reference: the classical row for baselineOp. KEM encaps/decaps map
   * to the X25519 key-agreement (derive) timing. */
  const base = rows.find(r => r.classical && r.operation === baselineOp);
  mkChart(canvasId, {
    type:"bar",
    data:{ labels:data.map(r=>r.alg),
      datasets:[{ label:title,
        data:data.map(r=>nsToMs(r.median_ns)),
        backgroundColor:data.map(r=> r.classical?BASE_COLOR:(LEVEL_COLORS[r.nist_level]||PQ_COLOR)) }] },
    options:{ responsive:true, plugins:{
        title:{display:true,text:title,color:"#e6e8ee"},
        legend:{display:false},
        tooltip:{callbacks:{
          label:(it)=>`median ${it.raw.toFixed(4)} ms (${Math.round(it.raw*1e6).toLocaleString()} ns)`,
          afterLabel:(it)=>{
          const r=data[it.dataIndex]; return `NIST L${r.nist_level} · ${r.classical?"classical baseline":"PQ"}`; }}},
        annotation: base ? baselineAnnotation(nsToMs(base.median_ns),
            baselineOp === op ? `baseline ${base.alg}` : `baseline ${base.alg} ${base.operation}`) : {} },
      scales:{ x:{ticks:{color:"#9aa3b2",maxRotation:50,minRotation:40,font:{size:10.5}}},
               y: logY ? logScale("median latency") : linScale("median latency (ms)") } }},
    { formatter:(v)=>fmtMs(v) });
}

function scatter(canvasId, rows, op, sizeKey, title, xlabel, logX = false) {
  const data = rows.filter(r => r.operation === op && r.sizes && r.sizes[sizeKey]);
  if (!data.length) return drawEmpty(canvasId, title);
  const pts = data.map(r => ({ x:r.sizes[sizeKey], y:nsToMs(r.median_ns), alg:r.alg, classical:r.classical }));
  mkChart(canvasId, {
    type:"scatter",
    data:{ datasets:[{ label:title, data:pts, pointRadius:6,
        backgroundColor:pts.map(p=>p.classical?BASE_COLOR:PQ_COLOR) }] },
    options:{ responsive:true, plugins:{
        title:{display:true,text:title,color:"#e6e8ee"}, legend:{display:false},
        tooltip:{callbacks:{label:(it)=>`${it.raw.alg}: ${it.raw.x} B, ${it.raw.y.toFixed(3)} ms`}} },
      scales:{ x: logX ? {type:"logarithmic",title:{display:true,text:`${xlabel} (log)`,color:"#9aa3b2"},ticks:{color:"#9aa3b2"}}
                       : linScale(xlabel),
               y: logScale("median latency") } }});
}

/* ---- absences --------------------------------------------------------------- */
function absencesPanel() {
  const el = $("absences"); el.innerHTML = "";
  const seen = new Set(); const items = [];
  const add = (kind, label, impl, reason, phase) => {
    const k = kind+impl+label+reason;
    if (seen.has(k)) return; seen.add(k);
    items.push({kind,label,impl,reason,phase});
  };
  (MERGED.tls_absent||[]).forEach(a=>add("TLS", a.label, a.implementation, a.reason, a.phase));
  (MERGED.kem_absent||[]).forEach(a=>add("KEM", a.alg, a.implementation, a.reason, ""));
  (MERGED.sig_absent||[]).forEach(a=>add("SIG", a.alg, a.implementation, a.reason, ""));
  // the substantive finding first
  items.sort((a,b)=>(/SLH-DSA/i.test(b.reason)?1:0)-(/SLH-DSA/i.test(a.reason)?1:0));
  if (!items.length) { el.innerHTML = '<div class="absence">none</div>'; return; }
  items.forEach(it => {
    const d = document.createElement("div");
    d.className = "absence";
    d.innerHTML = `<span class="impl">${it.impl}</span><b>${it.kind} · ${it.label}</b>` +
                  (it.phase?` <span class="impl">${it.phase}</span>`:"") +
                  `<br>${it.reason}`;
    el.appendChild(d);
  });
}

/* ---- helpers ---------------------------------------------------------------- */
function mkChart(canvasId, cfg, extras) {
  const ctx = $(canvasId).getContext("2d");
  const c = new Chart(ctx, cfg);
  if (extras) c.$pqb = extras;
  try { c.draw(); } catch (e) {
    console.error("chart failed:", canvasId, e);
    if (window.onerror) window.onerror(`chart ${canvasId}: ${e.message}`, "app.js", 0, 0, e);
  }
  CHARTS.push(c);
}
function drawEmpty(canvasId, msg) {
  const c = $(canvasId); const ctx = c.getContext("2d");
  ctx.clearRect(0,0,c.width,c.height);
  ctx.fillStyle = "#9aa3b2"; ctx.font = "13px sans-serif"; ctx.textAlign="center";
  ctx.fillText(msg, c.width/2, c.height/2);
}
function showEmpty(html) {
  document.querySelector("main").innerHTML = `<div class="empty">${html}</div>`;
}

boot();
