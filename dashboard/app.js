/* pq-bench-rpi5 dashboard — pure client-side, reads a merged.json produced by
 * analyze/merge.py. No backend. Renders KEM/sig/TLS charts with the classical
 * Logos baseline as a reference line on each. Defaults to baseline-grade (RPi5)
 * runs only; a toggle includes macOS/dev smoke runs. */

const LEVEL_COLORS = { 1:"#3bd67a", 2:"#46c0c0", 3:"#3a7bff", 5:"#b06bff", 0:"#888" };
const BASE_COLOR = "#e0533d", PQ_COLOR = "#3a7bff";
let MERGED = null, CHARTS = [];

const $ = (id) => document.getElementById(id);
const nsToMs = (ns) => (ns || 0) / 1e6;
/* compact ms label: more decimals for small values, fewer for large. Guards its
 * input — Chart.js may hand a value-label formatter a parsed {x,y} point or a
 * non-number; extract the numeric value without coercing an object (Number() on
 * a null-prototype object would itself throw), and return "" for anything not
 * finite so the value-label draw never throws and halts later charts. */
const fmtMs = (v) => {
  const ms = typeof v === "number" ? v
           : (v && typeof v === "object") ? (typeof v.y === "number" ? v.y : NaN)
           : Number(v);
  if (!Number.isFinite(ms)) return "";
  return ms>=100?ms.toFixed(0):ms>=10?ms.toFixed(1):ms>=1?ms.toFixed(2):ms.toFixed(3);
};

/* Inline Chart.js plugin: draw each bar's value just above the bar. Enabled
 * per-chart via options.plugins.valueLabels.formatter; charts that don't set it
 * are untouched (TLS/scatter stay clean). No external dependency, so it works
 * even when only the Chart.js core CDN is reachable. */
const valueLabels = {
  id: "valueLabels",
  afterDatasetsDraw(chart) {
    const opt = (chart.options.plugins||{}).valueLabels;
    if (!opt || !opt.formatter) return;
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
        ctx.fillText(opt.formatter(v, i), el.x, el.y - 3);
      });
    });
    ctx.restore();
  }
};
if (window.Chart) Chart.register(valueLabels);

async function boot() {
  $("fileInput").addEventListener("change", onFile);
  $("includeSmoke").addEventListener("change", render);
  $("runSelect").addEventListener("change", render);
  try {
    const r = await fetch("data/merged.json", { cache: "no-store" });
    if (r.ok) { MERGED = await r.json(); afterLoad(); }
    else showEmpty("No data/merged.json yet. Run a benchmark, then: " +
                   "<code>python3 analyze/merge.py results/*.json -o dashboard/data/merged.json</code> " +
                   "— or load a results file above.");
  } catch (e) {
    showEmpty("Could not auto-load data/merged.json (open via a local server or use the file picker).");
  }
}

function onFile(ev) {
  const f = ev.target.files[0]; if (!f) return;
  const rd = new FileReader();
  rd.onload = () => {
    const d = JSON.parse(rd.result);
    // accept either a merged file or a single results file
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
  const kem=[], sig=[], tls=[];
  (d.kem||[]).forEach(k=>{ if(k.enabled) Object.entries(k.operations||{}).forEach(([op,st])=>
     kem.push({...meta, alg:k.alg, classical:!!k.classical, nist_level:k.claimed_nist_level,
               operation:op, median_ns:st.median, sizes:k.sizes})); });
  (d.sig||[]).forEach(s=>{ if(s.enabled) Object.entries(s.operations||{}).forEach(([op,st])=>
     sig.push({...meta, alg:s.alg, classical:!!s.classical, nist_level:s.claimed_nist_level,
               operation:op, median_ns:st.median, sizes:s.sizes})); });
  ((d.tls||{}).matrix||[]).forEach(c=>{ if(c.enabled) tls.push({...meta, label:c.label, group:c.group,
     is_baseline_pair:c.label===((d.tls||{}).baseline||{}).label,
     handshakes_per_sec:c.handshakes_per_sec, median_ns:(c.handshake_latency_ns||{}).median,
     bytes_total:(c.bytes_on_wire||{}).total, client_hello_bytes:c.client_hello_bytes,
     client_hello_fragmented:c.client_hello_fragmented}); });
  return { merged_schema:"single", n_runs:1,
           runs:[{run_id:rid, host:d.host, is_baseline_grade:d.is_baseline_grade,
                  baseline_grade_reasons:d.baseline_grade_reasons||[], toolchain:d.toolchain,
                  cpu_features:d.cpu_features, run:d.run,
                  thermal_summary:{temp_c:(d.thermal_trace||{}).temp_c,
                                   throttling_detected:(d.thermal_trace||{}).throttling_detected},
                  generated_utc:d.generated_utc}],
           kem, sig, tls };
}

function afterLoad() {
  const sel = $("runSelect");
  sel.innerHTML = "";
  MERGED.runs.forEach(r => {
    const o = document.createElement("option");
    o.value = r.run_id;
    o.textContent = `${(r.host||{}).cpu_brand||"?"} — ${r.is_baseline_grade?"✅ baseline":"⚠ smoke"} — ${r.generated_utc||""}`;
    sel.appendChild(o);
  });
  render();
}

function currentRun() {
  const id = $("runSelect").value;
  return MERGED.runs.find(r => r.run_id === id) || MERGED.runs[0];
}

function render() {
  if (!MERGED) return;
  CHARTS.forEach(c => c.destroy()); CHARTS = [];
  const run = currentRun();
  const includeSmoke = $("includeSmoke").checked;
  const allowed = new Set(MERGED.runs
     .filter(r => includeSmoke || r.is_baseline_grade)
     .map(r => r.run_id));
  // chart the selected run if allowed, else fall back to allowed set
  const rid = allowed.has(run.run_id) ? run.run_id : null;
  const filt = (rows) => rows.filter(r => rid ? r.run_id === rid : allowed.has(r.run_id));

  renderBanner(run);
  renderEnv(run);

  const kem = filt(MERGED.kem), sig = filt(MERGED.sig), tls = filt(MERGED.tls);

  barByLevel("kem_keygen", kem, "keygen", "KEM keygen — median latency (ms)");
  barByLevel("kem_encaps", kem, "encaps", "KEM encaps — median latency (ms)", "derive");
  barByLevel("kem_decaps", kem, "decaps", "KEM decaps — median latency (ms)", "derive");
  scatter("kem_scatter", kem, "encaps", "public_key", "KEM size vs speed (encaps)", "public key (B)");
  barByLevel("sig_sign", sig, "sign", "Signature sign — median latency (ms)", "sign", true);
  barByLevel("sig_verify", sig, "verify", "Signature verify — median latency (ms)", "verify", true);
  scatter("sig_scatter", sig, "sign", "signature", "Signature size vs speed (sign)", "signature (B)", true);
  tlsThroughput("tls_hs", tls);
  tlsClientHello("tls_chello", tls);
}

function renderBanner(run) {
  const el = $("quality-banner");
  if (run.is_baseline_grade) {
    el.className = "banner-good";
    el.innerHTML = "✅ RPi5 baseline-grade run — performance governor, core-pinned, " +
                   "cortex-a76 flags, no thermal throttling.";
  } else {
    el.className = "banner-warn";
    const rs = (run.baseline_grade_reasons||[]).map(r=>`<li>${r}</li>`).join("");
    el.innerHTML = "⚠ NOT RPi5 baseline-grade — treat as a pipeline smoke test, not measurement data." +
                   (rs ? `<ul>${rs}</ul>` : "");
  }
}

function renderEnv(run) {
  const h = run.host||{}, t = run.toolchain||{}, f = run.cpu_features||{}, rn = run.run||{};
  const chip = (label, val) => `<span class="chip"><b>${label}</b> ${val}</span>`;
  const sha3 = f.sha3 ? "SHA3 hw ✓" : "SHA3 hw ✗ (Keccak on NEON)";
  $("env-summary").innerHTML = [
    chip("host", `${h.cpu_brand||"?"} (${h.os_pretty||h.os||"?"})`),
    chip("governor", rn.governor_after||"?"),
    chip("pinned core", rn.pinned ? rn.bench_core : "no"),
    chip("flags", `${t.bench_cflags||"?"} → ${t.cflags_target||"?"}`),
    chip("liboqs", `${t.liboqs_ref||"?"} ${(t.liboqs_commit||"").slice(0,8)}`),
    chip("crypto-ext", `${f.neon?"NEON ":""}${f.sha2?"SHA2 ":""}${sha3}`),
    chip("cycles", rn.cycles_available ? "PMU ✓" : "time-based"),
    chip("temp", run.thermal_summary && run.thermal_summary.temp_c
         ? `${run.thermal_summary.temp_c.mean}°C` + (run.thermal_summary.throttling_detected?" ⚠throttled":"")
         : "n/a"),
  ].join("");
}

/* ---- chart builders ----------------------------------------------------- */
function baselineAnnotation(value, label) {
  if (value == null) return {};
  return { annotations: { base: {
    type:"line", yMin:value, yMax:value, borderColor:BASE_COLOR,
    borderWidth:2, borderDash:[6,4],
    label:{ display:true, content:label, position:"end",
            backgroundColor:BASE_COLOR, font:{size:10} } } } };
}

function barByLevel(canvasId, rows, op, title, baselineOp = op, logY = false) {
  const data = rows.filter(r => r.operation === op)
                   .sort((a,b)=>(a.nist_level||0)-(b.nist_level||0) || a.median_ns-b.median_ns);
  if (!data.length) return drawEmpty(canvasId, title);
  /* Baseline reference line: the classical row for baselineOp (defaults to this
   * chart's own op). KEM encaps/decaps have no classical encaps/decaps op, so
   * they map to the X25519 key-agreement (derive) timing instead. */
  const base = rows.find(r => r.classical && r.operation === baselineOp);
  const ctx = $(canvasId).getContext("2d");
  CHARTS.push(new Chart(ctx, {
    type:"bar",
    data:{ labels:data.map(r=>r.alg),
      datasets:[{ label:title,
        data:data.map(r=>nsToMs(r.median_ns)),
        backgroundColor:data.map(r=> r.classical?BASE_COLOR:(LEVEL_COLORS[r.nist_level]||PQ_COLOR)) }] },
    options:{ responsive:true, plugins:{
        title:{display:true,text:title,color:"#e6e8ee"},
        legend:{display:false},
        valueLabels:{ formatter:(v)=>fmtMs(v) },
        tooltip:{callbacks:{
          label:(it)=>`median ${it.raw.toFixed(4)} ms (${Math.round(it.raw*1e6).toLocaleString()} ns)`,
          afterLabel:(it)=>{
          const r=data[it.dataIndex]; return `NIST L${r.nist_level} · ${r.classical?"classical baseline":"PQ"}`; }}},
        annotation: base ? baselineAnnotation(nsToMs(base.median_ns),
            baselineOp === op ? `baseline ${base.alg}` : `baseline ${base.alg} ${base.operation}`) : {} },
      scales:{ x:{ticks:{color:"#9aa3b2",maxRotation:50,minRotation:40}},
               y:{ type: logY?"logarithmic":"linear",
                   title:{display:true,text:logY?"ms (log)":"ms",color:"#9aa3b2"},ticks:{color:"#9aa3b2"}} } }
  }));
}

function scatter(canvasId, rows, op, sizeKey, title, xlabel, logScale = false) {
  const data = rows.filter(r => r.operation === op && r.sizes && r.sizes[sizeKey]);
  if (!data.length) return drawEmpty(canvasId, title);
  const pts = data.map(r => ({ x:r.sizes[sizeKey], y:nsToMs(r.median_ns), alg:r.alg, classical:r.classical }));
  const ctx = $(canvasId).getContext("2d");
  CHARTS.push(new Chart(ctx, {
    type:"scatter",
    data:{ datasets:[{ label:title, data:pts, pointRadius:6,
        backgroundColor:pts.map(p=>p.classical?BASE_COLOR:PQ_COLOR) }] },
    options:{ responsive:true, plugins:{
        title:{display:true,text:title,color:"#e6e8ee"}, legend:{display:false},
        tooltip:{callbacks:{label:(it)=>`${it.raw.alg}: ${it.raw.x} B, ${it.raw.y.toFixed(3)} ms`}} },
      scales:{ x:{ type: logScale?"logarithmic":"linear",
                   title:{display:true,text:logScale?`${xlabel} (log)`:xlabel,color:"#9aa3b2"},ticks:{color:"#9aa3b2"}},
               y:{ type: logScale?"logarithmic":"linear",
                   title:{display:true,text:logScale?"median latency (ms, log)":"median latency (ms)",color:"#9aa3b2"},ticks:{color:"#9aa3b2"}} } }
  }));
}

function tlsThroughput(canvasId, rows) {
  if (!rows.length) return drawEmpty(canvasId, "TLS handshakes/sec — run the TLS layer");
  const data = rows.slice().sort((a,b)=>(b.handshakes_per_sec||0)-(a.handshakes_per_sec||0));
  const base = data.find(r => r.is_baseline_pair);
  const ctx = $(canvasId).getContext("2d");
  CHARTS.push(new Chart(ctx, {
    type:"bar",
    data:{ labels:data.map(r=>r.label),
      datasets:[{ label:"handshakes/sec",
        data:data.map(r=>r.handshakes_per_sec),
        backgroundColor:data.map(r=>r.is_baseline_pair?BASE_COLOR:PQ_COLOR) }] },
    options:{ indexAxis:"y", responsive:true, plugins:{
        title:{display:true,text:"TLS 1.3 handshake throughput (higher = better)",color:"#e6e8ee"},
        legend:{display:false},
        annotation: base ? { annotations:{ base:{ type:"line",
            xMin:base.handshakes_per_sec, xMax:base.handshakes_per_sec,
            borderColor:BASE_COLOR, borderWidth:2, borderDash:[6,4],
            label:{display:true,content:`baseline ${base.label}`,position:"end",
                   backgroundColor:BASE_COLOR,font:{size:10}} } } } : {} },
      scales:{ x:{title:{display:true,text:"handshakes/sec",color:"#9aa3b2"},ticks:{color:"#9aa3b2"}},
               y:{ticks:{color:"#9aa3b2",font:{size:10}}} } }
  }));
}

function tlsClientHello(canvasId, rows) {
  if (!rows.length) return drawEmpty(canvasId, "ClientHello size — run the TLS layer");
  const data = rows.slice().sort((a,b)=>(b.client_hello_bytes||0)-(a.client_hello_bytes||0));
  const base = data.find(r => r.is_baseline_pair);
  const ctx = $(canvasId).getContext("2d");
  CHARTS.push(new Chart(ctx, {
    type:"bar",
    data:{ labels:data.map(r=>r.label),
      datasets:[{ label:"ClientHello bytes",
        data:data.map(r=>r.client_hello_bytes),
        backgroundColor:data.map(r=> r.is_baseline_pair?BASE_COLOR
            : (r.client_hello_fragmented?"#d98b2b":PQ_COLOR)) }] },
    options:{ indexAxis:"y", responsive:true, plugins:{
        title:{display:true,text:"ClientHello size (orange = exceeds ~1400B MSS → fragments)",color:"#e6e8ee"},
        legend:{display:false},
        annotation:{ annotations:{ mss:{ type:"line", xMin:1400, xMax:1400,
            borderColor:"#d98b2b", borderWidth:1, borderDash:[4,4],
            label:{display:true,content:"~MSS 1400B",position:"start",backgroundColor:"#d98b2b",font:{size:9}} },
            ...(base?{base:{type:"line",xMin:base.client_hello_bytes,xMax:base.client_hello_bytes,
            borderColor:BASE_COLOR,borderWidth:2,borderDash:[6,4],
            label:{display:true,content:`baseline ${base.label}`,position:"end",backgroundColor:BASE_COLOR,font:{size:10}}}}:{}) } } },
      scales:{ x:{title:{display:true,text:"bytes",color:"#9aa3b2"},ticks:{color:"#9aa3b2"}},
               y:{ticks:{color:"#9aa3b2",font:{size:10}}} } }
  }));
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
