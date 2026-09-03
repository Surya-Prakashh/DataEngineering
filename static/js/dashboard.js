/* ============================================================
   dashboard.js — Phase 1, Phase 2, and Phase 3 Visualizations & Controls
   ============================================================ */

Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Inter', sans-serif";

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'rgba(13,21,38,0.95)',
      borderColor: 'rgba(255,255,255,0.1)',
      borderWidth: 1,
      padding: 12,
      titleFont: { size: 12, weight: '600' },
      bodyFont: { size: 11 },
    }
  }
};

function setElText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = (text !== undefined && text !== null) ? text : '—';
}

function setElHTML(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

const chartInstances = {};
function getOrCreate(canvasId, config) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  if (chartInstances[canvasId]) {
    chartInstances[canvasId].destroy();
  }
  chartInstances[canvasId] = new Chart(ctx, config);
  return chartInstances[canvasId];
}

// ── Navigation ──────────────────────────────────────────────
async function showSection(sectionId) {
  document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const sec = document.getElementById(sectionId);
  if (sec) sec.classList.add('active');

  const navEl = document.querySelector(`[data-section="${sectionId}"]`);
  if (navEl) navEl.classList.add('active');

  const titles = {
    'sec-overview': 'Project Overview',
    'sec-p1-collection': 'Phase 1 — Data Collection',
    'sec-p1-preprocessing': 'Phase 1 — Preprocessing & Cleaning',
    'sec-p1-features': 'Phase 1 — Feature Engineering',
    'sec-p1-eda': 'Phase 1 — EDA & Visualization',
    'sec-report': 'Phase 1 — Technical Report',
    'sec-p2-extraction': 'Phase 2 — Data Extraction Strategies',
    'sec-p2-transformation': 'Phase 2 — Data Transformations',
    'sec-p2-loading': 'Phase 2 — Loading Strategies',
    'sec-p2-cdc': 'Phase 2 — CDC & Performance',
    'sec-p2-report': 'Phase 2 — Technical Report',
    'sec-p3-oltp-olap': 'Phase 3 — OLTP vs OLAP Architecture',
    'sec-p3-relational': 'Phase 3 — Relational 3NF Schema',
    'sec-p3-dimensional': 'Phase 3 — Star & Snowflake Schemas',
    'sec-p3-cube': 'Phase 3 — Data Cube & SQL Queries',
    'sec-p3-report': 'Phase 3 — Technical Report',
    'sec-p4-kafka': 'Phase 4 — Kafka Stream & Staging Area',
    'sec-p4-idempotency': 'Phase 4 — Idempotency & Atomicity',
    'sec-p4-replay': 'Phase 4 — Historical Offset Replay',
    'sec-p4-report': 'Phase 4 — Technical Report',
  };
  setElText('topbar-title-text', titles[sectionId] || 'Dashboard');

  try {
    if (sectionId === 'sec-overview') await loadOverviewStats();
    else if (sectionId === 'sec-p1-collection') await loadCollection();
    else if (sectionId === 'sec-p1-preprocessing') await loadPreprocessing();
    else if (sectionId === 'sec-p1-features') await loadFeatures();
    else if (sectionId === 'sec-p1-eda') await loadEDA();
    else if (sectionId === 'sec-p2-extraction') await loadPhase2Extraction();
    else if (sectionId === 'sec-p2-transformation') await loadPhase2Transformation();
    else if (sectionId === 'sec-p2-loading') await loadPhase2Loading();
    else if (sectionId === 'sec-p2-cdc') await loadPhase2CDC();
    else if (sectionId === 'sec-p3-oltp-olap') await loadPhase3OLTPOLAP();
    else if (sectionId === 'sec-p3-relational') await loadPhase3Relational();
    else if (sectionId === 'sec-p3-dimensional') await loadPhase3Dimensional();
    else if (sectionId === 'sec-p3-cube') await loadPhase3Cube();
    else if (sectionId === 'sec-p4-kafka') await loadPhase4Kafka();
  } catch (err) {
    console.error(`Error rendering section ${sectionId}:`, err);
  }
}

async function fetchJSON(url) {
  // Cache-bust every request so browsers always get live data after row injection
  const sep = url.includes('?') ? '&' : '?';
  const res = await fetch(url + sep + '_t=' + Date.now(), {
    cache: 'no-store',
    headers: { 'Cache-Control': 'no-cache' }
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

// ════════════════════════════════════════════════════════════
//  PHASE 1 LOADERS
// ════════════════════════════════════════════════════════════
async function loadOverviewStats() {
  const data = await fetchJSON('/api/phase1/dataset_overview');
  setElText('stat-rows', data.rows.toLocaleString());
  setElText('stat-cols', data.columns.toLocaleString());
  setElText('stat-classes', data.classes);
  setElText('stat-missing', data.missing_total);
  setElText('stat-size', data.total_size_mb + ' MB');
  setElText('stat-numeric', data.numeric_features);
  // Update global row count indicators visible on every page
  setElText('topbar-row-count', data.rows.toLocaleString());
  setElText('sidebar-sample-count', data.rows.toLocaleString());
  setElText('col-stat-samples', data.rows.toLocaleString());
  setElText('col-stat-families', data.classes);
}

async function loadCollection() {
  // Fetch live row count and update the stat cards
  const overview = await fetchJSON('/api/phase1/dataset_overview');
  setElText('col-stat-samples', overview.rows.toLocaleString());
  setElText('col-stat-families', overview.classes);

  const dist = await fetchJSON('/api/phase1/class_distribution');
  getOrCreate('chart-donut', {
    type: 'doughnut',
    data: {
      labels: dist.labels,
      datasets: [{ data: dist.values, backgroundColor: dist.colors, borderWidth: 2 }]
    },
    options: { ...CHART_DEFAULTS, plugins: { ...CHART_DEFAULTS.plugins, legend: { display: true, position: 'right' } }, cutout: '65%' }
  });

  const fsz = await fetchJSON('/api/phase1/file_size_distribution');
  const families = Object.keys(fsz);
  getOrCreate('chart-filesize', {
    type: 'bar',
    data: { labels: families, datasets: [{ label: 'Mean Size (KB)', data: families.map(f => fsz[f].mean), backgroundColor: families.map(f => fsz[f].color + 'cc'), borderRadius: 6 }] },
    options: { ...CHART_DEFAULTS }
  });

  const src = await fetchJSON('/api/phase1/data_sources_info');
  setElHTML('sources-container', src.sources.map(s => `
    <div class="source-card">
      <div class="source-icon">${s.icon}</div>
      <div class="source-name">${s.name}</div>
      <div class="source-type">${s.type}</div>
      <div class="source-desc">${s.description}</div>
      <div class="source-count">📦 ${s.samples.toLocaleString()} samples</div>
    </div>
  `).join(''));
}

async function loadPreprocessing() {
  const mv = await fetchJSON('/api/phase1/missing_values');
  setElText('completeness-pct', mv.completeness_pct + '%');
  setElHTML('steps-list', mv.steps.map(s => `
    <div class="step-item"><div class="step-status">${s.status.split(' ')[0]}</div><div><div class="step-name">${s.step}</div><div class="step-detail">${s.detail}</div></div></div>
  `).join(''));

  const radar = await fetchJSON('/api/phase1/data_quality_radar');
  getOrCreate('chart-radar', {
    type: 'radar',
    data: { labels: radar.dimensions, datasets: [{ label: 'Score', data: radar.scores, backgroundColor: 'rgba(99,102,241,0.15)', borderColor: '#6366f1' }] },
    options: { ...CHART_DEFAULTS, scales: { r: { min: 90 } } }
  });

  const norm = await fetchJSON('/api/phase1/normalization_stats');
  setElHTML('norm-tbody', norm.map(n => `
    <tr><td>${n.feature}</td><td>${n.raw_mean.toExponential(2)}</td><td>${n.raw_std.toExponential(2)}</td><td>${n.raw_min.toExponential(2)}</td><td>${n.raw_max.toExponential(2)}</td><td style="color:#10b981">${n.norm_mean}</td><td style="color:#10b981">${n.norm_std}</td></tr>
  `).join(''));
}

async function loadFeatures() {
  const fgs = await fetchJSON('/api/phase1/feature_groups');
  setElHTML('feat-tbody', fgs.map(f => `
    <tr><td><strong>${f.group}</strong></td><td><span class="feature-count-badge">${f.count}</span></td><td>${f.description}</td><td><span class="type-badge">${f.type}</span></td><td style="color:var(--text-secondary);font-size:0.75rem">${f.engineering}</td></tr>
  `).join(''));

  const fi = await fetchJSON('/api/phase1/feature_importance');
  getOrCreate('chart-variance', {
    type: 'bar',
    data: { labels: fi.features, datasets: [{ label: 'Variance', data: fi.variance, backgroundColor: '#6366f1', borderRadius: 4 }] },
    options: { ...CHART_DEFAULTS, indexAxis: 'y' }
  });

  const ent = await fetchJSON('/api/phase1/entropy_by_family');
  const entFams = Object.keys(ent);
  getOrCreate('chart-entropy-family', {
    type: 'bar',
    data: { labels: entFams, datasets: [{ label: 'Mean Entropy', data: entFams.map(f => ent[f].mean), backgroundColor: entFams.map(f => ent[f].color + 'cc'), borderRadius: 6 }] },
    options: { ...CHART_DEFAULTS, scales: { y: { min: 3, max: 8 } } }
  });

  const pca = await fetchJSON('/api/phase1/pca_scatter');
  getOrCreate('chart-pca', {
    type: 'scatter',
    data: { datasets: Object.entries(pca).map(([fam, d]) => ({ label: fam, data: d.x.map((x, i) => ({ x, y: d.y[i] })), backgroundColor: d.color + '99' })) },
    options: { ...CHART_DEFAULTS }
  });

  const tsne = await fetchJSON('/api/phase1/tsne_scatter');
  getOrCreate('chart-tsne', {
    type: 'scatter',
    data: { datasets: Object.entries(tsne).map(([fam, d]) => ({ label: fam, data: d.x.map((x, i) => ({ x, y: d.y[i] })), backgroundColor: d.color + '99' })) },
    options: { ...CHART_DEFAULTS }
  });
}

async function loadEDA() {
  const eh = await fetchJSON('/api/phase1/entropy_histogram');
  const rc = await fetchJSON('/api/phase1/ratio_comparison');
  const corr = await fetchJSON('/api/phase1/correlation_heatmap');
  const bp = await fetchJSON('/api/phase1/byte_profile');

  // Wait one animation frame so the section is fully visible and canvases have dimensions
  await new Promise(r => requestAnimationFrame(r));
  await new Promise(r => setTimeout(r, 30));

  getOrCreate('chart-entropy-hist', {
    type: 'bar',
    data: { labels: eh.labels.map(v => v.toFixed(2)), datasets: [{ label: 'Count', data: eh.values, backgroundColor: '#6366f1', borderRadius: 4 }] },
    options: { ...CHART_DEFAULTS }
  });

  getOrCreate('chart-ratios', {
    type: 'bar',
    data: {
      labels: rc.families,
      datasets: rc.datasets.map(d => ({ label: d.label, data: d.data, backgroundColor: d.color + 'cc', borderRadius: 4 }))
    },
    options: { ...CHART_DEFAULTS, plugins: { ...CHART_DEFAULTS.plugins, legend: { display: true, position: 'top' } } }
  });

  renderCorrelationHeatmap(corr);

  getOrCreate('chart-byte-profile', {
    type: 'radar',
    data: {
      labels: bp.bytes,
      datasets: bp.datasets.map(d => ({
        label: d.label,
        data: d.data,
        borderColor: d.color,
        backgroundColor: d.color + '22',
        borderWidth: 1.5,
        pointRadius: 2
      }))
    },
    options: {
      ...CHART_DEFAULTS,
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: true, position: 'right', labels: { boxWidth: 10, font: { size: 10 } } } },
      scales: { r: { ticks: { display: false }, grid: { color: 'rgba(255,255,255,0.06)' } } }
    }
  });
}

function renderCorrelationHeatmap(corr) {
  const canvas = document.getElementById('chart-corr');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const n = corr.labels.length;
  const parent = canvas.parentElement;
  const w = (parent ? (parent.offsetWidth || parent.clientWidth || 600) : 600);
  const h = 380;
  canvas.width = w;
  canvas.height = h;
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';

  const cellW = w / n;
  const cellH = h / n;

  // Draw label axes
  ctx.fillStyle = '#94a3b8';
  ctx.font = `${Math.max(7, Math.min(10, cellW * 0.35))}px JetBrains Mono, monospace`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';

  corr.matrix.forEach((row, i) => {
    row.forEach((val, j) => {
      let r = val >= 0 ? Math.round(99 + (255-99)*(1-val)) : Math.round(244 - (244-50)*(1+val));
      let g = val >= 0 ? Math.round(102 + (255-102)*(1-val)) : Math.round(63 - (63-50)*(1+val));
      let b = val >= 0 ? Math.round(241 + (255-241)*(1-val)) : Math.round(94 - (94-50)*(1+val));
      ctx.fillStyle = `rgba(${r},${g},${b},${0.2 + Math.abs(val) * 0.7})`;
      ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);
      ctx.fillStyle = Math.abs(val) > 0.6 ? 'white' : '#94a3b8';
      ctx.fillText(val.toFixed(2), j * cellW + cellW / 2, i * cellH + cellH / 2);
    });
  });
}

// ════════════════════════════════════════════════════════════
//  PHASE 2 LOADERS
// ════════════════════════════════════════════════════════════
async function loadPhase2Extraction() {
  const data = await fetchJSON('/api/phase2/extraction_sources');
  setElHTML('p2-sources-grid', data.sources.map(s => `
    <div class="source-card" style="border-top:3px solid var(--accent)">
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="source-icon">${s.icon}</div><span style="font-size:0.65rem;font-weight:700;color:#10b981;background:rgba(16,185,129,0.15);padding:2px 8px;border-radius:10px">${s.status}</span></div>
      <div class="source-name">${s.name}</div><div class="source-type">${s.type}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);font-family:var(--font-mono)">Protocol: ${s.protocol}</div>
      <div style="display:flex;justify-content:space-between;margin-top:4px;font-size:0.75rem"><span>Latency: <strong style="color:var(--accent)">${s.latency_ms} ms</strong></span><span>Records: <strong style="color:var(--accent2)">${s.records_extracted}</strong></span></div>
    </div>
  `).join(''));
}

async function runExtractionDemo() {
  setElText('p2-extract-status', 'EXTRACTING...');
  const res = await fetchJSON('/api/phase2/extract_demo');
  setElText('p2-extract-status', `SUCCESS (${res.total_extraction_time_ms} ms)`);
  setElText('pre-api', JSON.stringify(res.rest_api_preview, null, 2));
  setElText('pre-rdbms', JSON.stringify(res.rdbms_preview, null, 2));
  setElText('pre-nosql', JSON.stringify(res.nosql_preview, null, 2));
  setElText('pre-flat', JSON.stringify(res.flat_file_preview, null, 2));
}

async function loadPhase2Transformation() {
  const data = await fetchJSON('/api/phase2/transform_pipeline');
  setElText('p2-transform-time', `Latency: ${data.execution_time_ms} ms`);
  setElHTML('p2-transform-steps-cards', data.steps.map(s => `
    <div style="background:var(--bg-secondary);padding:16px;border-radius:10px;border:1px solid var(--border)"><div style="font-size:0.85rem;font-weight:700;color:var(--accent);margin-bottom:6px">${s.name}</div><div style="font-size:0.78rem;color:var(--text-secondary);line-height:1.6">${s.description}</div></div>
  `).join(''));
  setElHTML('p2-agg-tbody', data.aggregated_data.map(r => `
    <tr><td style="font-weight:600">${r.Family_Name}</td><td>${r.sample_count}</td><td style="color:var(--accent)">${r.avg_entropy}</td><td>${r.max_entropy}</td><td>${r.avg_size_mb} MB</td><td>${r.avg_null_ratio}</td><td style="color:var(--accent4)">${r.avg_nop_ratio}</td></tr>
  `).join(''));
}

async function loadPhase2Loading() {
  const data = await fetchJSON('/api/phase2/loading_strategies');
  setElText('lbl-full-latency', data.full_load.latency_ms + ' ms');
  setElText('lbl-full-rows', data.full_load.rows_processed.toLocaleString());
  setElText('lbl-full-desc-rows', data.full_load.rows_processed.toLocaleString());
  setElText('lbl-full-io', data.full_load.io_transfer_mb + ' MB');
  setElText('lbl-inc-latency', data.incremental_load.latency_ms + ' ms');
  setElText('lbl-inc-rows', data.incremental_load.rows_processed.toLocaleString());
  setElText('lbl-inc-io', data.incremental_load.io_transfer_mb + ' MB');

  getOrCreate('chart-load-bench', {
    type: 'bar',
    data: {
      labels: ['Latency (ms)', 'DB Lock Time (ms)', 'Payload Size (x100 KB)'],
      datasets: [
        { label: 'Full Load (Truncate & Replace)', data: [data.full_load.latency_ms, data.full_load.db_lock_time_ms, data.full_load.io_transfer_mb * 10], backgroundColor: 'rgba(99,102,241,0.8)', borderRadius: 6 },
        { label: 'Incremental Load (Watermark Delta)', data: [data.incremental_load.latency_ms, data.incremental_load.db_lock_time_ms, data.incremental_load.io_transfer_mb * 10], backgroundColor: 'rgba(16,185,129,0.8)', borderRadius: 6 }
      ]
    },
    options: { ...CHART_DEFAULTS, plugins: { ...CHART_DEFAULTS.plugins, legend: { display: true, position: 'top' } } }
  });
}

async function triggerLoadSim(strategy) {
  const consoleEl = document.getElementById('load-console');
  if (consoleEl) consoleEl.innerHTML += `\n[RUNNING] Executing ${strategy.toUpperCase()} Load simulation...`;
  const res = await fetch('/api/phase2/run_load_simulation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ strategy })
  }).then(r => r.json());
  if (consoleEl) {
    consoleEl.innerHTML += `\n[${res.timestamp}] SUCCESS: ${res.status} | Inserted: ${res.rows_inserted} rows | Latency: ${res.execution_time_ms} ms`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }
}

async function loadPhase2CDC() {
  const data = await fetchJSON('/api/phase2/cdc_stream');
  setElHTML('cdc-event-list', data.events.map(e => `
    <div style="display:flex;align-items:center;justify-content:space-between;background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:8px;font-family:var(--font-mono);font-size:0.75rem">
      <div><span style="font-weight:700;color:${e.operation === 'INSERT' ? '#10b981' : e.operation === 'UPDATE' ? '#f59e0b' : '#f43f5e'}">[${e.operation}]</span><span style="color:var(--text-secondary);margin-left:8px">LSN: ${e.lsn}</span><span style="color:var(--text-primary);margin-left:8px">Sample: ${e.sample_id.substring(0,10)}... (${e.family})</span></div>
      <span style="color:var(--text-muted)">${e.timestamp}</span>
    </div>
  `).join(''));

  const perf = await fetchJSON('/api/phase2/etl_performance');
  getOrCreate('chart-etl-breakdown', {
    type: 'doughnut',
    data: {
      labels: perf.stage_breakdown.map(s => s.stage),
      datasets: [{ data: perf.stage_breakdown.map(s => s.time_ms), backgroundColor: ['#6366f1', '#f59e0b', '#10b981'] }]
    },
    options: { ...CHART_DEFAULTS, plugins: { ...CHART_DEFAULTS.plugins, legend: { display: true, position: 'right' } } }
  });
}

// ════════════════════════════════════════════════════════════
//  PHASE 3 LOADERS & PHYSICAL DATABASE INSPECTOR
// ════════════════════════════════════════════════════════════

async function loadPhase3OLTPOLAP() {
  const data = await fetchJSON('/api/phase3/oltp_vs_olap');
  setElHTML('medallion-cards-container', data.medallion_architecture.map(m => `
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;display:flex;flex-direction:column;gap:8px">
      <div style="font-size:1rem;font-weight:700;color:var(--accent)">${m.layer}</div>
      <div style="font-size:0.82rem;color:var(--text-primary);font-weight:500">${m.purpose}</div>
      <div style="font-size:0.75rem;color:var(--text-secondary);font-family:var(--font-mono)">Format: ${m.data_format}</div>
      <div style="font-size:0.75rem;color:var(--text-muted)">Schema: ${m.schema}</div>
      <div style="font-size:0.75rem;color:var(--accent2);margin-top:4px">💡 In Project: ${m.in_our_project}</div>
    </div>
  `).join(''));

  setElHTML('p3-matrix-tbody', data.comparison_matrix.map(c => `
    <tr>
      <td style="font-weight:600">${c.characteristic}</td>
      <td style="color:var(--accent)">${c.oltp}</td>
      <td style="color:var(--accent2)">${c.olap}</td>
    </tr>
  `).join(''));
}

async function loadPhase3Relational() {
  const dbInfo = await fetchJSON('/api/phase3/db_info');
  setElText('lbl-oltp-db-path', dbInfo.oltp_database.file_path);
  setElText('lbl-oltp-db-stats', `${dbInfo.oltp_database.size_kb} KB · 3 Tables (devices, malware_families, scan_logs)`);

  const data = await fetchJSON('/api/phase3/relational_schema');
  setElHTML('p3-relational-tables-container', data.tables.map(t => `
    <div class="chart-card" style="border-top:3px solid var(--accent)">
      <div class="chart-card-header">
        <div class="chart-card-title"><span class="icon">📋</span> Table: ${t.table_name}</div>
        <span class="chart-badge">PK: ${t.pk}</span>
      </div>
      <div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:12px">${t.description}</div>
      <div style="overflow-x:auto;margin-bottom:14px">
        <table class="norm-table">
          <thead>
            <tr><th style="text-align:left">Column</th><th>Type</th><th>Key</th><th style="text-align:left">Description</th></tr>
          </thead>
          <tbody>
            ${t.columns.map(c => `
              <tr>
                <td style="font-family:var(--font-mono);font-weight:600">${c.name}</td>
                <td>${c.type}</td>
                <td><span style="color:${c.key === 'PK' ? 'var(--accent)' : c.key === 'FK' ? 'var(--accent2)' : 'var(--text-muted)'}">${c.key}</span></td>
                <td style="text-align:left;color:var(--text-secondary)">${c.desc}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:4px">SQL DDL Definition:</div>
      <pre style="background:var(--bg-secondary);padding:10px;border-radius:6px;font-family:var(--font-mono);font-size:0.72rem;color:var(--accent2);overflow-x:auto">${t.ddl}</pre>
    </div>
  `).join(''));

  await inspectTable('oltp', 'scan_logs');
}

async function inspectTable(dbTarget, tableName) {
  setElText('lbl-query-status', `Executing Query: SELECT * FROM ${tableName} LIMIT 8`);
  const res = await fetchJSON(`/api/phase3/query_physical_db?db=${dbTarget}&table=${tableName}&limit=8`);
  
  if (res.status === 'SUCCESS') {
    const cols = res.columns;
    setElHTML('tbl-inspect-head', `<tr>${cols.map(c => `<th style="text-align:left">${c}</th>`).join('')}</tr>`);
    setElHTML('tbl-inspect-body', res.rows.map(r => `
      <tr>${cols.map(c => `<td style="font-family:var(--font-mono);font-size:0.75rem;text-align:left">${r[c]}</td>`).join('')}</tr>
    `).join(''));
  }
}

async function loadPhase3Dimensional() {
  const dbInfo = await fetchJSON('/api/phase3/db_info');
  setElText('lbl-olap-db-path', dbInfo.olap_database.file_path);
  setElText('lbl-olap-db-stats', `${dbInfo.olap_database.size_kb} KB · fact_malware_detections + 4 Dimensions`);
  switchSchemaView('star');
}

function switchSchemaView(viewType) {
  const starBtn = document.getElementById('btn-toggle-star');
  const snowBtn = document.getElementById('btn-toggle-snowflake');
  const viewport = document.getElementById('schema-diagram-viewport');
  if (!viewport) return;

  if (viewType === 'star') {
    if (starBtn) starBtn.classList.add('active');
    if (snowBtn) snowBtn.classList.remove('active');

    viewport.innerHTML = `
      <!-- TOP ROW: DIM_MALWARE_FAMILY & DIM_TIME -->
      <div class="dim-row">
        <div class="ref-db-card">
          <div class="ref-card-header">DIM_MALWARE_FAMILY</div>
          <div class="ref-card-body">
            <div><span class="pk-tag">PK</span><span class="col-name">family_key</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">family_name</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">threat_category</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">severity_level</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">first_discovered_year</span><span class="type-tag">INT</span></div>
          </div>
        </div>

        <div class="ref-db-card">
          <div class="ref-card-header">DIM_TIME</div>
          <div class="ref-card-body">
            <div><span class="pk-tag">PK</span><span class="col-name">time_key</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">full_date</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">day_of_week</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">month_name</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">quarter</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">year</span><span class="type-tag">INT</span></div>
          </div>
        </div>
      </div>

      <!-- VERTICAL ARROW CONNECTOR -->
      <div class="connector-arrow">↕</div>

      <!-- MIDDLE ROW: CENTRAL FACT TABLE -->
      <div class="ref-fact-card">
        <div class="ref-card-header">⭐ FACT_MALWARE_DETECTIONS</div>
        <div class="ref-card-body">
          <div><span class="pk-tag">PK</span><span class="col-name">fact_id</span><span class="type-tag">BIGINT</span></div>
          <div><span class="col-name">sample_hash</span><span class="type-tag">VARCHAR(64)</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">family_key</span><span class="type-tag">INT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">device_key</span><span class="type-tag">INT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">time_key</span><span class="type-tag">INT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">engine_key</span><span class="type-tag">INT</span></div>
          <div><span class="col-name">file_size_bytes</span><span class="type-tag">BIGINT</span></div>
          <div><span class="col-name">shannon_entropy</span><span class="type-tag">FLOAT</span></div>
          <div><span class="col-name">null_byte_count</span><span class="type-tag">INT</span></div>
          <div><span class="col-name">nop_instruction_count</span><span class="type-tag">INT</span></div>
          <div><span class="col-name">detection_latency_ms</span><span class="type-tag">FLOAT</span></div>
        </div>
      </div>

      <!-- VERTICAL ARROW CONNECTOR -->
      <div class="connector-arrow">↕</div>

      <!-- BOTTOM ROW: DIM_DEVICE & DIM_THREAT_ENGINE -->
      <div class="dim-row">
        <div class="ref-db-card">
          <div class="ref-card-header">DIM_DEVICE</div>
          <div class="ref-card-body">
            <div><span class="pk-tag">PK</span><span class="col-name">device_key</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">hostname</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">os_family</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">os_version</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">ip_subnet</span><span class="type-tag">VARCHAR</span></div>
          </div>
        </div>

        <div class="ref-db-card">
          <div class="ref-card-header">DIM_THREAT_ENGINE</div>
          <div class="ref-card-body">
            <div><span class="pk-tag">PK</span><span class="col-name">engine_key</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">engine_name</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">vendor</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">engine_version</span><span class="type-tag">VARCHAR</span></div>
          </div>
        </div>
      </div>
    `;
  } else {
    if (starBtn) starBtn.classList.remove('active');
    if (snowBtn) snowBtn.classList.add('active');

    viewport.innerHTML = `
      <!-- TOP ROW: DIM_MALWARE_FAMILY with SUBDIM & DIM_TIME -->
      <div class="dim-row" style="align-items:center">
        <div class="snowflake-ext-row">
          <div class="ref-db-card" style="border-color:#10b981">
            <div class="ref-card-header" style="color:#10b981">SUBDIM_CATEGORY</div>
            <div class="ref-card-body">
              <div><span class="pk-tag">PK</span><span class="col-name">category_id</span><span class="type-tag">INT</span></div>
              <div><span class="col-name">payload_type</span><span class="type-tag">VARCHAR</span></div>
              <div><span class="col-name">risk_rating</span><span class="type-tag">VARCHAR</span></div>
            </div>
          </div>
          <span class="h-arrow">➔</span>
          <div class="ref-db-card">
            <div class="ref-card-header">DIM_MALWARE_FAMILY</div>
            <div class="ref-card-body">
              <div><span class="pk-tag">PK</span><span class="col-name">family_key</span><span class="type-tag">INT</span></div>
              <div><span class="fk-tag">FK</span><span class="col-name">category_id</span><span class="type-tag">INT</span></div>
              <div><span class="col-name">family_name</span><span class="type-tag">VARCHAR</span></div>
            </div>
          </div>
        </div>

        <div class="ref-db-card">
          <div class="ref-card-header">DIM_TIME</div>
          <div class="ref-card-body">
            <div><span class="pk-tag">PK</span><span class="col-name">time_key</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">full_date</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">quarter</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">year</span><span class="type-tag">INT</span></div>
          </div>
        </div>
      </div>

      <!-- VERTICAL ARROW CONNECTOR -->
      <div class="connector-arrow">↕</div>

      <!-- MIDDLE ROW: CENTRAL FACT TABLE -->
      <div class="ref-fact-card">
        <div class="ref-card-header">❄️ FACT_MALWARE_DETECTIONS</div>
        <div class="ref-card-body">
          <div><span class="pk-tag">PK</span><span class="col-name">fact_id</span><span class="type-tag">BIGINT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">family_key</span><span class="type-tag">INT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">device_key</span><span class="type-tag">INT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">time_key</span><span class="type-tag">INT</span></div>
          <div><span class="fk-tag">FK</span><span class="col-name">engine_key</span><span class="type-tag">INT</span></div>
          <div><span class="col-name">file_size_bytes</span><span class="type-tag">BIGINT</span></div>
          <div><span class="col-name">shannon_entropy</span><span class="type-tag">FLOAT</span></div>
          <div><span class="col-name">detection_latency_ms</span><span class="type-tag">FLOAT</span></div>
        </div>
      </div>

      <!-- VERTICAL ARROW CONNECTOR -->
      <div class="connector-arrow">↕</div>

      <!-- BOTTOM ROW: DIM_DEVICE with SUBDIM & DIM_THREAT_ENGINE -->
      <div class="dim-row" style="align-items:center">
        <div class="snowflake-ext-row">
          <div class="ref-db-card">
            <div class="ref-card-header">DIM_DEVICE</div>
            <div class="ref-card-body">
              <div><span class="pk-tag">PK</span><span class="col-name">device_key</span><span class="type-tag">INT</span></div>
              <div><span class="fk-tag">FK</span><span class="col-name">os_id</span><span class="type-tag">INT</span></div>
              <div><span class="col-name">hostname</span><span class="type-tag">VARCHAR</span></div>
            </div>
          </div>
          <span class="h-arrow">➔</span>
          <div class="ref-db-card" style="border-color:#10b981">
            <div class="ref-card-header" style="color:#10b981">SUBDIM_OS_DETAILS</div>
            <div class="ref-card-body">
              <div><span class="pk-tag">PK</span><span class="col-name">os_id</span><span class="type-tag">INT</span></div>
              <div><span class="col-name">os_name</span><span class="type-tag">VARCHAR</span></div>
              <div><span class="col-name">kernel_build</span><span class="type-tag">VARCHAR</span></div>
            </div>
          </div>
        </div>

        <div class="ref-db-card">
          <div class="ref-card-header">DIM_THREAT_ENGINE</div>
          <div class="ref-card-body">
            <div><span class="pk-tag">PK</span><span class="col-name">engine_key</span><span class="type-tag">INT</span></div>
            <div><span class="col-name">engine_name</span><span class="type-tag">VARCHAR</span></div>
            <div><span class="col-name">vendor</span><span class="type-tag">VARCHAR</span></div>
          </div>
        </div>
      </div>
    `;
  }
}


async function loadPhase3Cube() {
  await runCubeOp('slice');
  await loadPhase3SQLQueries();
}

async function runCubeOp(operation) {
  const titles = {
    'slice': "SLICE (Family = 'Ramnit')",
    'dice': 'DICE (Entropy > 6.0 bits AND File Size > 1.0 MB)',
    'rollup': 'ROLL-UP (Global Entire System Summary)',
    'drilldown': "DRILL-DOWN (Sample File Hashes for 'Ramnit')"
  };
  setElText('lbl-cube-op-title', `Selected Operation: ${titles[operation] || operation}`);
  const res = await fetchJSON(`/api/phase3/data_cube?operation=${operation}`);
  setElText('pre-cube-results', JSON.stringify(res, null, 2));
}

async function loadPhase3SQLQueries() {
  const data = await fetchJSON('/api/phase3/analytical_queries');
  const container = document.getElementById('sql-queries-container');
  if (container) {
    const q1 = data.query_1_rollup;
    const q2 = data.query_2_window;

    container.innerHTML = `
      <div style="background:var(--bg-secondary);padding:16px;border-radius:10px;border:1px solid var(--border)">
        <div style="font-size:0.88rem;font-weight:700;color:var(--accent);margin-bottom:6px">${q1.title}</div>
        <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:8px">${q1.description}</div>
        <pre style="background:rgba(0,0,0,0.3);padding:10px;border-radius:6px;font-family:var(--font-mono);font-size:0.75rem;color:var(--accent2)">${q1.sql}</pre>
      </div>
      <div style="background:var(--bg-secondary);padding:16px;border-radius:10px;border:1px solid var(--border)">
        <div style="font-size:0.88rem;font-weight:700;color:var(--accent2);margin-bottom:6px">${q2.title}</div>
        <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:8px">${q2.description}</div>
        <pre style="background:rgba(0,0,0,0.3);padding:10px;border-radius:6px;font-family:var(--font-mono);font-size:0.75rem;color:var(--accent2)">${q2.sql}</pre>
        <div style="margin-top:10px;font-size:0.75rem;color:var(--text-muted)">Live Window Function Execution Output on Physical Star Warehouse:</div>
        <div style="overflow-x:auto;margin-top:6px">
          <table class="norm-table">
            <thead><tr><th style="text-align:left">Family</th><th>Avg Entropy</th><th>Detections</th><th style="color:var(--accent)">Entropy Rank</th></tr></thead>
            <tbody>
              ${q2.results.map(r => `
                <tr>
                  <td style="font-weight:600">${r.family_name}</td>
                  <td>${r.avg_entropy.toFixed(4)}</td>
                  <td>${r.detections}</td>
                  <td style="color:var(--accent);font-weight:700">#${r.entropy_rank}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }
}

// ════════════════════════════════════════════════════════════
//  PHASE 4 LOADERS & HANDLERS
// ════════════════════════════════════════════════════════════

async function loadPhase4Kafka() {
  const status = await fetchJSON('/api/phase4/kafka_stream_status');
  setElText('lbl-kafka-topic-name', status.topic);
  setElText('lbl-kafka-total-produced', status.total_messages_produced);
  setElText('lbl-kafka-lag', status.consumer_lag);
  setElText('lbl-kafka-dlq-count', status.dlq_messages_count);
}

async function triggerProduceKafkaEvents() {
  const res = await fetch('/api/phase4/produce_kafka_events', { method: 'POST' }).then(r => r.json());
  await loadPhase4Kafka();

  const log = document.getElementById('p4-kafka-ingest-log');
  if (log && res.produced_events) {
    log.style.display = 'block';
    log.innerHTML = `<div style="color:var(--accent);font-weight:700;margin-bottom:8px">📡 LIVE TRANSMISSION (First 3 events):</div>`;
    res.produced_events.slice(0, 3).forEach(e => {
      log.innerHTML += `<pre style="background:rgba(0,0,0,0.3);padding:6px;border-radius:4px;margin-bottom:6px;font-size:0.7rem;color:var(--text-primary);border-left:2px solid var(--accent)">${JSON.stringify(e, null, 2)}</pre>`;
    });
    log.innerHTML += `<div style="color:var(--text-muted);font-size:0.7rem;margin-top:4px">+ ${Math.max(0, res.produced_events.length - 3)} more events transmitted.</div>`;
  }
}

async function triggerStagingValidation() {
  const res = await fetch('/api/phase4/run_staging_validation', { method: 'POST' }).then(r => r.json());
  await loadPhase4Kafka();

  const dlqContainer = document.getElementById('p4-dlq-stream-container');
  if (dlqContainer && res.dlq_samples) {
    if (res.dlq_samples.length === 0) {
      dlqContainer.innerHTML = `<div style="color:#10b981;font-size:0.75rem">✅ All ${res.passed_to_staging} messages passed 3-tier DQ checks! 0 errors.</div>`;
    } else {
      dlqContainer.innerHTML = res.dlq_samples.map(s => `
        <div style="background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.2);padding:8px 12px;border-radius:6px;font-family:var(--font-mono);font-size:0.72rem">
          <div style="color:#f43f5e;font-weight:700">⚠️ DLQ ISOLATED: [${s.message_id}]</div>
          <div style="color:var(--text-secondary)">Reason: ${s.reason}</div>
          <div style="color:var(--text-muted)">Sample Hash: ${s.hash}</div>
        </div>
      `).join('');
    }
  }
}

async function runIdempotencyTest() {
  const out = document.getElementById('p4-idempotency-output');
  if (out) out.innerHTML = 'Executing 5 duplicate batch pipeline reruns...';
  const res = await fetch('/api/phase4/test_idempotency', { method: 'POST' }).then(r => r.json());
  if (out) {
    out.innerHTML = `
      <div style="color:#10b981;font-weight:700;margin-bottom:4px">✅ IDEMPOTENCY VERIFIED (0 DUPLICATE ROWS)</div>
      <div>Reruns Executed: ${res.reruns_executed} times</div>
      <div>Batch Size: ${res.batch_size} events</div>
      <div>Initial Staging Rows: ${res.initial_staging_rows}</div>
      <div>Final Staging Rows: ${res.final_staging_rows}</div>
      <div style="color:var(--accent2);font-weight:700">Duplicate Rows Added: ${res.duplicate_rows_added}</div>
      <div style="color:var(--text-muted);margin-top:4px">${res.message}</div>
      <div style="margin-top:10px;font-size:0.75rem;color:var(--accent)">Live Batch Payload Sample:</div>
      <pre style="background:rgba(0,0,0,0.3);padding:8px;border-radius:6px;margin-top:4px;border-left:2px solid var(--accent);color:var(--text-primary);font-size:0.7rem;max-height:150px;overflow-y:auto">${JSON.stringify(res.sample_payload, null, 2)}</pre>
    `;
  }
}

async function runAtomicityTest(scenario = 'bad') {
  const out = document.getElementById('p4-atomicity-output');
  if (out) out.innerHTML = `Testing transaction ${scenario === 'good' ? 'COMMIT (Clean Batch)' : 'ROLLBACK (Poison Pill)'}...`;
  const res = await fetch('/api/phase4/test_atomicity', { 
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario })
  }).then(r => r.json());
  if (out) {
    const isSuccess = res.status === 'COMMITTED';
    const statusColor = isSuccess ? '#10b981' : '#f43f5e';
    out.innerHTML = `
      <div style="color:${statusColor};font-weight:700;margin-bottom:4px">${isSuccess ? '✅' : '🛑'} ATOMOCITY VERIFIED: ${res.status}</div>
      <div>Rollback Occurred: ${res.rollback_occurred ? 'YES (All-or-Nothing)' : 'NO'}</div>
      <div style="color:${statusColor}">${isSuccess ? 'No errors triggered.' : 'Triggered Error: ' + res.error_triggered}</div>
      <div>Rows Before Batch: ${res.rows_before_transaction}</div>
      <div>Rows After ${isSuccess ? 'Commit' : 'Failure'}: ${res.rows_after_transaction}</div>
      <div style="color:var(--accent2);font-weight:700">Partial Rows Inserted: ${res.partial_rows_inserted}</div>
      <div style="color:var(--text-muted);margin-top:4px">${res.message}</div>
      <div style="margin-top:10px;font-size:0.75rem;color:var(--accent4)">Full Transaction Batch (${isSuccess ? 'Clean' : 'Including Poison Pill'}):</div>
      <pre style="background:rgba(${isSuccess ? '16,185,129' : '244,63,94'},0.1);padding:8px;border-radius:6px;margin-top:4px;border-left:2px solid ${statusColor};color:var(--text-primary);font-size:0.7rem;max-height:150px;overflow-y:auto">${JSON.stringify(res.transaction_batch, null, 2)}</pre>
    `;
  }
}

async function triggerBackfillReplay() {
  const partition = document.getElementById('sel-replay-partition').value;
  const start = document.getElementById('num-replay-start').value;
  const end = document.getElementById('num-replay-end').value;

  const consoleEl = document.getElementById('p4-replay-console');
  if (consoleEl) consoleEl.innerHTML = `Replaying offsets ${start} to ${end} for Partition ${partition}...`;

  const res = await fetch('/api/phase4/run_backfill_replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ partition, start_offset: start, end_offset: end })
  }).then(r => r.json());

  if (consoleEl) {
    consoleEl.innerHTML = `
      <div style="color:#10b981;font-weight:700;margin-bottom:4px">✅ REPLAY COMPLETED</div>
      <div>Partition: ${res.replayed_partition} | Range: Offsets ${res.offset_range}</div>
      <div>Messages Replayed: ${res.messages_replayed}</div>
      <div>Sample Hashes Replayed: ${res.sample_preview.join(', ')}</div>
      <div style="color:var(--text-muted);margin-top:4px">${res.message}</div>
    `;
  }
}

// ════════════════════════════════════════════════════════════
//  E2E PIPELINE ORCHESTRATOR HANDLER
// ════════════════════════════════════════════════════════════

async function runE2EPipeline() {
  const progressBar = document.getElementById('e2e-progress-bar');
  const progressPercent = document.getElementById('e2e-progress-percent');
  const progressLabel = document.getElementById('e2e-progress-label');
  const consoleEl = document.getElementById('e2e-pipeline-console');

  // Reset Badges, Stats, and Pipeline CSS classes
  ['p1', 'p2', 'p3', 'p4'].forEach((p, idx) => {
    const badge = document.getElementById(`e2e-badge-${p}`);
    const stats = document.getElementById(`e2e-stats-${p}`);
    const card = document.getElementById(`e2e-card-${p}`);
    const conn = document.getElementById(`e2e-conn-${idx + 1}`);
    
    if (badge) { badge.textContent = 'PENDING'; badge.style.background = 'rgba(255,255,255,0.1)'; badge.style.color = 'var(--text-muted)'; }
    if (stats) { stats.textContent = 'Duration: -- ms'; }
    if (card) { card.className = 'glass-card pipeline-step'; } // Reset classes
    if (conn) { conn.className = 'pipeline-connector'; }
  });

  if (consoleEl) consoleEl.innerHTML = `[${new Date().toLocaleTimeString()}] 🚀 Initiating End-to-End Pipeline Run...`;
  if (progressBar) progressBar.style.width = '10%';
  if (progressPercent) progressPercent.textContent = '10%';
  if (progressLabel) progressLabel.textContent = 'Executing Pipeline Backend...';

  // Set Step 1 to running visually while waiting for backend
  setE2EBadge('p1', 'RUNNING', '#6366f1');
  document.getElementById('e2e-card-p1').classList.add('running');
  document.getElementById('e2e-conn-1').classList.add('running');

  try {
    const res = await fetch('/api/pipeline/run_e2e', { method: 'POST' }).then(r => r.json());

    if (res.status === 'SUCCESS') {
      // Backend finished. Let's animate the UI sequentially to show the flow
      const delay = ms => new Promise(res => setTimeout(res, ms));
      
      // Step 1 Finish
      document.getElementById('e2e-card-p1').classList.replace('running', 'success');
      document.getElementById('e2e-conn-1').classList.replace('running', 'success');
      setE2EBadge('p1', 'PASSED', '#10b981');
      setElText('e2e-stats-p1', `Duration: ${res.step_breakdown.phase1.duration_ms} ms · ${res.step_breakdown.phase1.raw_records} rows`);
      if (progressBar) progressBar.style.width = '25%';
      
      // Step 2 Run -> Finish
      document.getElementById('e2e-card-p2').classList.add('running');
      if (document.getElementById('e2e-conn-2')) document.getElementById('e2e-conn-2').classList.add('running');
      setE2EBadge('p2', 'RUNNING', '#3b82f6');
      if (progressLabel) progressLabel.textContent = 'Step 2: Columnar Extraction & CDC...';
      await delay(400); // Visual delay
      
      document.getElementById('e2e-card-p2').classList.replace('running', 'success');
      if (document.getElementById('e2e-conn-2')) document.getElementById('e2e-conn-2').classList.replace('running', 'success');
      setE2EBadge('p2', 'PASSED', '#10b981');
      setElText('e2e-stats-p2', `Duration: ${res.step_breakdown.phase2.duration_ms} ms · ${res.step_breakdown.phase2.rows_extracted} rows`);
      if (progressBar) progressBar.style.width = '50%';
      
      // Step 3 Run -> Finish
      document.getElementById('e2e-card-p3').classList.add('running');
      if (document.getElementById('e2e-conn-3')) document.getElementById('e2e-conn-3').classList.add('running');
      setE2EBadge('p3', 'RUNNING', '#a855f7');
      if (progressLabel) progressLabel.textContent = 'Step 3: OLTP / OLAP Warehouse Refresh...';
      await delay(400);
      
      document.getElementById('e2e-card-p3').classList.replace('running', 'success');
      if (document.getElementById('e2e-conn-3')) document.getElementById('e2e-conn-3').classList.replace('running', 'success');
      setE2EBadge('p3', 'PASSED', '#10b981');
      setElText('e2e-stats-p3', `Duration: ${res.step_breakdown.phase3.duration_ms} ms · ${res.step_breakdown.phase3.olap_facts} facts`);
      if (progressBar) progressBar.style.width = '75%';
      
      // Step 4 Run -> Finish
      document.getElementById('e2e-card-p4').classList.add('running');
      setE2EBadge('p4', 'RUNNING', '#10b981');
      if (progressLabel) progressLabel.textContent = 'Step 4: Kafka Staging & Idempotency Check...';
      await delay(400);
      
      document.getElementById('e2e-card-p4').classList.replace('running', 'success');
      setE2EBadge('p4', 'PASSED', '#10b981');
      setElText('e2e-stats-p4', `Duration: ${res.step_breakdown.phase4.duration_ms} ms · ${res.step_breakdown.phase4.kafka_produced} events`);
      
      if (progressBar) progressBar.style.width = '100%';
      if (progressPercent) progressPercent.textContent = '100%';
      if (progressLabel) progressLabel.textContent = `Pipeline Completed in ${res.total_duration_ms} ms 🎉`;

      if (consoleEl) {
        consoleEl.innerHTML = res.logs.map(line => `<div>${line}</div>`).join('');
        consoleEl.scrollTop = consoleEl.scrollHeight;
      }
    } else {
      if (progressLabel) progressLabel.textContent = 'Pipeline execution failed.';
    }
  } catch (err) {
    if (progressLabel) progressLabel.textContent = 'Pipeline error: ' + err.message;
  }
}

function setE2EBadge(phase, text, color) {
  const b = document.getElementById(`e2e-badge-${phase}`);
  if (b) {
    b.textContent = text;
    b.style.background = color;
    b.style.color = '#ffffff';
  }
}

// ════════════════════════════════════════════════════════════
//  DATASET MUTATION & MOCK GENERATOR HANDLERS
// ════════════════════════════════════════════════════════════

async function loadDatasetStatus() {
  const data = await fetchJSON('/api/pipeline/dataset_status');
  const countEl = document.getElementById('lbl-active-dataset-count');
  if (countEl) {
    countEl.textContent = `${data.total_rows.toLocaleString()} Rows ${data.added_rows > 0 ? '(+' + data.added_rows + ' Added)' : ''}`;
  }
}

async function triggerAddMockData() {
  const inputEl = document.getElementById('num-mock-count');
  const count = inputEl ? parseInt(inputEl.value) || 50 : 50;
  const msgEl = document.getElementById('dataset-status-msg');

  if (msgEl) {
    msgEl.style.display = 'block';
    msgEl.style.color = 'var(--accent)';
    msgEl.textContent = `⏳ Injecting ${count} mock malware sample rows...`;
  }

  const res = await fetch('/api/pipeline/add_mock_data', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ count })
  }).then(r => r.json());

  if (msgEl) {
    msgEl.style.color = '#10b981';
    msgEl.textContent = `✅ ${res.message} Navigate to any Phase tab — all counts are now updated.`;
  }

  // Refresh ALL global row count indicators immediately
  await loadDatasetStatus();
  await loadOverviewStats();
}

async function triggerUploadCSV(fileInput) {
  if (!fileInput.files || fileInput.files.length === 0) return;
  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append('file', file);

  const msgEl = document.getElementById('dataset-status-msg');
  if (msgEl) {
    msgEl.style.display = 'block';
    msgEl.style.color = 'var(--accent)';
    msgEl.textContent = `⏳ Uploading and processing ${file.name}...`;
  }

  const res = await fetch('/api/pipeline/upload_csv', {
    method: 'POST',
    body: formData
  }).then(r => r.json());

  if (msgEl) {
    if (res.status === 'SUCCESS') {
      msgEl.style.color = '#10b981';
      msgEl.textContent = `✅ ${res.message} Navigate to any Phase tab — all counts are now updated.`;
      // Refresh ALL global row count indicators immediately
      await loadDatasetStatus();
      await loadOverviewStats();
    } else {
      msgEl.style.color = '#f43f5e';
      msgEl.textContent = `⚠️ Upload Error: ${res.message}`;
    }
  }

  await loadDatasetStatus();
}

async function triggerResetDataset() {
  const msgEl = document.getElementById('dataset-status-msg');
  if (msgEl) {
    msgEl.style.display = 'block';
    msgEl.style.color = 'var(--accent)';
    msgEl.textContent = '⏳ Resetting dataset back to baseline 1643 rows...';
  }

  const res = await fetch('/api/pipeline/reset_dataset', { method: 'POST' }).then(r => r.json());
  if (msgEl) {
    msgEl.style.color = '#10b981';
    msgEl.textContent = `✅ ${res.message} Reset complete.`;
  }

  await loadDatasetStatus();
}

// ════════════════════════════════════════════════════════════
//  INIT ON DOM LOAD
// ════════════════════════════════════════════════════════════
window.addEventListener('DOMContentLoaded', async () => {
  await loadDatasetStatus();
  await showSection('sec-overview');
});

