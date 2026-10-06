// app.js — WiFi Analyzer UI front-end

const state = {
  devices: [],
  alerts: [],
  filter: 'all',
  search: '',
  tab: 'devices',
  ws: null,
  suspectsHideUnknown: true,
  suspectsStableOnly:  true,
  suspectsRssi: -45,
  alertTimer: 60,
};

// ─── helpers ───────────────────────────────────────────────

const $  = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function toast(msg, kind='info') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'fixed bottom-4 right-4 px-4 py-2 rounded shadow-lg text-sm border ' +
    (kind === 'error' ? 'bg-rose-50 border-rose-200 text-rose-700' :
     kind === 'ok'    ? 'bg-emerald-50 border-emerald-200 text-emerald-700' :
                        'bg-white border-gray-200 text-gray-700');
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 3000);
}

function fmtDateTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

function rssiBar(rssi) {
  if (rssi == null) return '—';
  const pct = Math.max(0, Math.min(100, ((rssi + 90) / 50) * 100));
  const color = rssi > -50 ? 'bg-rose-500'
              : rssi > -65 ? 'bg-amber-500'
              :              'bg-emerald-500';
  return `<span class="inline-flex items-center gap-2">
    <span class="bar ${color}" style="width:${pct.toFixed(0)}px"></span>
    <span class="font-mono text-xs">${rssi.toFixed(0)}</span>
  </span>`;
}

function statusBadge(d) {
  if (d.is_safe)           return '<span class="badge badge-safe">Safe</span>';
  if (d.is_infrastructure) return '<span class="badge badge-known">Known AP</span>';
  if (d.alert_sent)        return '<span class="badge badge-alert">Alert</span>';
  if (d.in_red_zone)       return '<span class="badge badge-zone">Red zone</span>';
  return '<span class="badge badge-seen">Seen</span>';
}

function rowClass(d) {
  if (d.alert_sent)        return 'row-alert';
  if (d.is_safe)           return 'row-safe';
  if (d.in_red_zone)       return 'row-redzone';
  return '';
}

function deviceType(d) {
  if (d.is_ap) return 'AP';
  return 'Client';
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

// ─── render ────────────────────────────────────────────────

function renderDevices() {
  const tbody = $('#device-tbody');
  const term = state.search.toLowerCase();
  const byFp = new Map();
  for (const d of state.devices) {
    const fp = d.fingerprint || d.mac;
    const ex = byFp.get(fp);
    if (!ex || (d.rssi_avg ?? -100) > (ex.rssi_avg ?? -100)) byFp.set(fp, d);
  }
  let rows = [...byFp.values()].filter(d => {
    if (state.filter === 'redzone' && !d.in_red_zone) return false;
    if (state.filter === 'ap'      && !d.is_ap)       return false;
    if (state.filter === 'unknown' && (d.is_safe || d.is_infrastructure)) return false;
    if (term) {
      const hay = (d.mac + ' ' + (d.manuf||'') + ' ' +
                   (d.probed_ssids||[]).join(' ') + ' ' +
                   (d.advertised_ssids||[]).join(' ')).toLowerCase();
      if (!hay.includes(term)) return false;
    }
    return true;
  });

  // Sort: alerts first, then red zone, then by RSSI desc
  rows.sort((a, b) => {
    if (a.alert_sent !== b.alert_sent) return b.alert_sent - a.alert_sent;
    if (a.in_red_zone !== b.in_red_zone) return b.in_red_zone - a.in_red_zone;
    return (b.rssi_avg ?? -100) - (a.rssi_avg ?? -100);
  });

  if (rows.length === 0) {
    tbody.innerHTML = '';
    $('#empty-devices').classList.remove('hidden');
    return;
  }
  $('#empty-devices').classList.add('hidden');

  tbody.innerHTML = rows.map(d => {
    const rotBadge = d.known_mac_count > 1
      ? `<span class="chip ml-1 bg-gray-100 text-gray-600">+${d.known_mac_count - 1} more MACs</span>`
      : '';
    const ssids = d.is_ap
      ? (d.advertised_ssids || []).map(s => `<span class="text-blue-700">${escapeHtml(s)}</span>`).join(' ')
      : (d.probed_ssids   || []).map(s => `<span class="text-gray-600">${escapeHtml(s)}</span>`).join(' ');
    const apConf = d.ap_confirmed ? '<span class="chip bg-emerald-100 text-emerald-700 ml-1" title="Kismet-confirmed association to an office AP">assoc</span>' : '';
    return `<tr class="${rowClass(d)}">
      <td class="px-3 py-2 text-xs whitespace-nowrap">${statusBadge(d)}${apConf}</td>
      <td class="px-3 py-2 font-mono text-xs">${escapeHtml(d.mac)}${rotBadge}</td>
      <td class="px-3 py-2 text-xs">${deviceType(d)}</td>
      <td class="px-3 py-2 text-xs text-gray-500 whitespace-nowrap">${escapeHtml(d.device_type || '—')}</td>
      <td class="px-3 py-2 text-right">${rssiBar(d.rssi_avg ?? d.rssi)}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${escapeHtml(d.manuf || '')}</td>
      <td class="px-3 py-2 text-xs">${ssids || '<span class="text-gray-400">—</span>'}</td>
      <td class="px-3 py-2 text-right text-xs font-mono">${d.seconds_in_zone || 0}s</td>
      <td class="px-3 py-2 text-right text-xs">
        ${!d.is_safe && !d.is_ap         ? `<button class="btn-emp btn btn-primary btn-sm" data-mac="${d.mac}">+Employee</button>` : ''}
        ${!d.is_infrastructure && d.is_ap ? `<button class="btn-infra btn btn-muted btn-sm ml-1" data-mac="${d.mac}">+Known AP</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

function renderSuspects() {
  const tbody = $('#suspects-tbody');
  // Deduplicate by fingerprint — keep the entry with the strongest signal
  const byFp = new Map();
  for (const d of state.devices) {
    if (d.is_safe || d.is_infrastructure || !d.in_red_zone) continue;
    const fp = d.fingerprint || d.mac;
    const existing = byFp.get(fp);
    if (!existing || (d.rssi_avg ?? -100) > (existing.rssi_avg ?? -100)) {
      byFp.set(fp, d);
    }
  }
  const all = [...byFp.values()];

  // Tighter RSSI threshold from the dropdown
  const rssiCutoff = state.suspectsRssi;
  // Identified = has probed SSIDs OR has been around > 30s (worth investigating)
  const identifiedOnly = state.suspectsHideUnknown;

  let suspects = all.filter(d => {
    const rssi = d.rssi_avg ?? d.rssi ?? -100;
    if (rssi <= rssiCutoff) return false;

    // Smart hide of LOW-CONFIDENCE fingerprints:
    //   - tier 'mac' (per-MAC fallback) only shown when strong signal OR persistent
    //   - tier 'weak' shown unless signal weak AND short-lived
    //   - tier 'medium'/'strong'/'wps_' always shown
    if (state.suspectsStableOnly) {
      const tier = d.confidence_tier || 'mac';
      const strongSignal = rssi > -42;
      const persistent   = (d.seconds_in_zone || 0) >= 30;
      if (tier === 'mac' && !strongSignal && !persistent) return false;
      if (tier === 'weak' && !strongSignal && !persistent && !(d.probed_ssids||[]).length) return false;
    }

    if (identifiedOnly) {
      const hasProbes = (d.probed_ssids || []).length > 0;
      const longLived = (d.seconds_in_zone || 0) >= 30;
      const strongSignal = rssi > -42;
      // Even "unidentified" should pass if very close — they're definitely here
      if (!hasProbes && !longLived && !strongSignal) return false;
    }
    return true;
  });

  suspects.sort((a, b) => (b.seconds_in_zone || 0) - (a.seconds_in_zone || 0));

  // Summary line uses the FILTERED count, not the raw count
  $('#suspects-summary').textContent =
    `${suspects.length} shown · ${all.length - suspects.length} hidden (rotation noise / weak signal)`;

  if (suspects.length === 0) {
    tbody.innerHTML = '';
    $('#empty-suspects').classList.remove('hidden');
    return;
  }
  $('#empty-suspects').classList.add('hidden');

  tbody.innerHTML = suspects.map(d => {
    const timer = state.alertTimer || 60;
    const secs  = d.seconds_in_zone || 0;
    const pct   = Math.min(100, (secs / timer) * 100);
    const barColor = (d.alert_sent || secs >= timer) ? 'bg-rose-500'
                   : secs >= timer / 2               ? 'bg-amber-500'
                   :                                   'bg-emerald-500';
    const timerCell = (d.alert_sent || secs >= timer)
      ? `<span class="text-rose-600 font-semibold text-xs">⚡ Alert sent</span>`
      : `<div class="inline-flex items-center gap-2">
           <span class="font-mono text-xs">${secs.toFixed(0)}s / ${timer}s</span>
           <span class="bar ${barColor}" style="width:${pct.toFixed(0)}px"></span>
         </div>`;
    const ssids = (d.probed_ssids || []).map(escapeHtml).join(', ') || '<span class="text-gray-400">—</span>';

    // MAC + rotation count: profile.known_macs.length tells us how many distinct
    // MACs this same fingerprint has used — a strong sign of MAC randomization
    const rotBadge = d.known_mac_count > 1
      ? `<span class="chip ml-1 bg-gray-100 text-gray-600">+${d.known_mac_count - 1} more MACs</span>`
      : '';
    const tier = d.confidence_tier || 'mac';
    const tierColor = tier === 'strong' ? 'bg-emerald-100 text-emerald-700'
                    : tier === 'medium' ? 'bg-amber-100 text-amber-700'
                    : tier === 'weak'   ? 'bg-orange-100 text-orange-700'
                    :                     'bg-gray-100 text-gray-600';
    const tierBadge = `<span class="chip ml-1 ${tierColor}" title="fingerprint confidence (score ${d.confidence_score ?? 0})">${tier}</span>`;

    // Associated AP — most reliable identifier when MAC rotates
    let assocCell;
    if (d.last_bssid_label) {
      assocCell = `<span class="text-emerald-700">✓ ${escapeHtml(d.last_bssid_label)}</span>
                   <div class="text-[10px] text-slate-500 font-mono">${escapeHtml(d.last_bssid)}</div>`;
    } else if (d.last_bssid) {
      assocCell = `<span class="text-amber-700">⚠ unknown AP</span>
                   <div class="text-[10px] text-slate-500 font-mono">${escapeHtml(d.last_bssid)}</div>`;
    } else {
      assocCell = '<span class="text-slate-500 text-xs">not associated</span>';
    }

    return `<tr class="${(d.alert_sent || secs >= timer) ? 'row-alert' : 'row-redzone'}">
      <td class="px-3 py-2 font-mono text-xs">${escapeHtml(d.mac)}${rotBadge}${tierBadge}</td>
      <td class="px-3 py-2 text-xs text-gray-500">${escapeHtml(d.device_type || '—')}</td>
      <td class="px-3 py-2 text-xs">${assocCell}</td>
      <td class="px-3 py-2 text-right">${rssiBar(d.rssi_avg ?? d.rssi)}</td>
      <td class="px-3 py-2 text-right">
        ${timerCell}
      </td>
      <td class="px-3 py-2 text-xs">${ssids}</td>
      <td class="px-3 py-2 text-right text-xs space-x-1">
        <button class="btn-monitor btn btn-muted btn-sm"
                data-fp="${escapeHtml(d.fingerprint || '')}"
                data-mac="${escapeHtml(d.mac)}">👁 Monitor</button>
        <button class="btn-emp btn btn-primary btn-sm" data-mac="${escapeHtml(d.mac)}">+Employee</button>
      </td>
    </tr>`;
  }).join('');
}

function renderAlertsCounter() {
  // unique fingerprints with alerts + sum of all occurrences, shown in the page title
  const unique = state.alerts.length;
  const total  = state.alerts.reduce((s, a) => s + (a.data.count || 1), 0);
  const el     = $('#alerts-count');
  if (!el) return;
  el.textContent = unique > 0 ? `(${unique} · ${total} occurrences)` : '';
}

function renderAlerts() {
  renderAlertsCounter();
  const list = $('#alert-list');
  // Newest first: alerts that just bumped float to the top
  const items = state.alerts.slice().sort((a, b) => b.ts - a.ts);
  if (items.length === 0) {
    list.innerHTML = '';
    $('#empty-alerts').classList.remove('hidden');
    return;
  }
  $('#empty-alerts').classList.add('hidden');
  list.innerHTML = items.map(a => {
    const d = a.data || {};
    const color = d.alert_type === 'EVIL_TWIN'     ? 'border-rose-500 bg-rose-50' :
                  d.alert_type === 'ROGUE_AP'      ? 'border-orange-500 bg-orange-50' :
                  d.alert_type === 'SPOOFED_AP'    ? 'border-amber-500 bg-amber-50' :
                                                     'border-yellow-500 bg-yellow-50';
    // "Time in zone" only makes sense for UNKNOWN_CLIENT (the only timer-based alert).
    // AP-based alerts (ROGUE_AP/EVIL_TWIN/SPOOFED_AP) fire instantly on the first beacon.
    const extra = [];
    // AP-type alerts: show the SSID(s) the AP is broadcasting + channel.
    const apAlert = ['ROGUE_AP', 'EVIL_TWIN', 'SPOOFED_AP'].includes(d.alert_type);
    if (apAlert) {
      const adv = (d.advertised_ssids || []).map(escapeHtml).join(', ');
      if (adv) extra.push(`<div class="text-xs">📡 AP broadcasts: <b>${adv}</b></div>`);
      else extra.push(`<div class="text-xs text-slate-500">📡 AP broadcasts: <i>(hidden / no SSID captured)</i></div>`);
      if (d.channel) extra.push(`<div class="text-xs">Channel: ${escapeHtml(d.channel)}</div>`);
    }
    if (d.spoofed_ssid) extra.push(`<div class="text-xs">Spoofed SSID: <b>${escapeHtml(d.spoofed_ssid)}</b></div>`);
    if (d.spoof_reason) extra.push(`<div class="text-xs">Reason: ${escapeHtml(d.spoof_reason)}</div>`);
    if (d.alert_type === 'UNKNOWN_CLIENT' && d.seconds_present) {
      const s = d.seconds_present.toFixed?.(0) || d.seconds_present;
      extra.push(`<div class="text-xs text-slate-300">⏱ Was in red zone <b>${s}s</b> when alert fired</div>`);
    }
    const extraHtml = extra.join('');
    const countBadge = (d.count && d.count > 1)
      ? `<span class="ml-2 px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded text-xs font-mono">×${d.count}</span>`
      : '';
    const firstSeen = (d.first_ts && d.count > 1)
      ? `<div class="text-xs text-slate-500">First seen: ${fmtDateTime(d.first_ts)}</div>`
      : '';
    return `<div class="border-l-4 rounded p-3 ${color}">
      <div class="flex items-baseline justify-between">
        <span class="font-bold">${d.alert_type}${countBadge}</span>
        <div class="flex items-center gap-2">
          <span class="text-xs text-slate-400 font-mono">${fmtDateTime(a.ts)}</span>
          <button class="btn-monitor btn btn-muted btn-sm"
                  data-fp="${escapeHtml(d.fingerprint || '')}"
                  data-mac="${escapeHtml(d.mac || '')}">👁 Monitor</button>
          <button class="btn-ignore btn btn-muted btn-sm"
                  data-type="${escapeHtml(d.alert_type)}"
                  data-fp="${escapeHtml(d.fingerprint || '')}"
                  data-mac="${escapeHtml(d.mac || '')}"
                  title="Permanently ignore this exact alert">🚫 Ignore</button>
        </div>
      </div>
      <div class="text-xs font-mono mt-1">${escapeHtml(d.mac || '')} <span class="text-slate-500">fp=${escapeHtml(d.fingerprint||'')}</span></div>
      ${d.device_type ? `<div class="text-xs text-slate-300">Device class: ${escapeHtml(d.device_type)}</div>` : ''}
      <div class="text-xs">RSSI ${d.rssi_avg?.toFixed?.(0)} dBm · probes: ${(d.probed_ssids||[]).map(escapeHtml).join(', ') || '—'}</div>
      ${firstSeen}
      ${extraHtml}
    </div>`;
  }).join('');
}

function renderWhitelist(data) {
  $('#emp-count').textContent   = `(${data.employees.length})`;
  $('#infra-count').textContent = `(${data.infrastructure.length})`;

  $('#employee-tbody').innerHTML = data.employees.map(e => `
    <tr>
      <td class="px-3 py-2 font-mono text-xs">${escapeHtml(e.fingerprint)}</td>
      <td class="px-3 py-2 font-mono text-xs text-slate-400">${e.known_macs.map(escapeHtml).join(', ')}</td>
      <td class="px-3 py-2 text-right">
        <button class="btn-rm-emp btn btn-danger btn-sm" data-fp="${escapeHtml(e.fingerprint)}">Remove</button>
      </td>
    </tr>`).join('');

  $('#infra-tbody').innerHTML = data.infrastructure.map(i => `
    <tr>
      <td class="px-3 py-2 font-mono text-xs">${escapeHtml(i.mac)}</td>
      <td class="px-3 py-2 text-xs">${escapeHtml(i.label || '—')}</td>
      <td class="px-3 py-2 text-xs">${(i.ssids || []).map(escapeHtml).join(', ')}</td>
      <td class="px-3 py-2 text-xs">${escapeHtml(i.channel || '—')}</td>
      <td class="px-3 py-2 text-right">
        <button class="btn-rm-infra btn btn-danger btn-sm" data-mac="${escapeHtml(i.mac)}">Remove</button>
      </td>
    </tr>`).join('');

  $('#ssid-list').innerHTML = (data.office_ssids || []).map(s =>
    `<span class="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs">${escapeHtml(s)}</span>`
  ).join('');
}

// ─── live status dot ───────────────────────────────────────
// The UI has no header; a small dot per page shows engine+WS liveness.

function updateStatusDots() {
  const live = (state.wsOk && state.running) ? '1' : '0';
  $$('.status-dot').forEach(d => {
    d.setAttribute('data-live', live);
    d.setAttribute('title', live === '1' ? 'live' : 'offline');
  });
}
function setStatus(running) { state.running = !!running; updateStatusDots(); }
function setWsStatus(ok)    { state.wsOk = !!ok; updateStatusDots(); }

// ─── view routing (URL-driven; the iframe is opened per view) ──

const VIEWS = ['devices', 'suspects', 'alerts', 'whitelist', 'setup'];

function viewFromUrl() {
  const v = new URLSearchParams(location.search).get('view') || location.hash.replace('#', '');
  return VIEWS.includes(v) ? v : 'devices';
}

function showView(name) {
  if (!VIEWS.includes(name)) name = 'devices';
  state.tab = name;
  $$('.tab-panel').forEach(p => p.classList.toggle('hidden', p.id !== 'tab-' + name));
  try {
    const u = new URL(location);
    u.searchParams.set('view', name);
    history.replaceState({}, '', u);
  } catch (e) { /* ignore */ }
  if (name === 'alerts')    { renderAlerts(); refreshAlertsHistory(); }
  if (name === 'whitelist')   refreshWhitelist();
  if (name === 'setup')     { refreshSetupAPs(); loadSettings(); refreshIgnores(); }
  if (name === 'suspects')    renderSuspects();
  if (name === 'devices')     renderDevices();
}

// ─── settings load/save ────────────────────────────────────

async function loadSettings() {
  try {
    const s = await api('/api/settings');
    $('#set-rssi'      ).value   = s.rssi_red_zone;
    $('#set-hysteresis')?.setAttribute('value', s.rssi_exit_offset_db);
    if ($('#set-hysteresis')) $('#set-hysteresis').value = s.rssi_exit_offset_db;
    $('#set-timer'     ).value   = s.alert_timer_seconds;
    $('#set-cooldown'  ).value   = s.alert_cooldown_seconds;
    $('#set-offset'    ).value   = s.dynamic_offset_db;
    $('#set-dynamic'   ).checked = !!s.use_dynamic_threshold;
    state.alertTimer = s.alert_timer_seconds || 60;
    const enabled = new Set(s.enabled_alerts || []);
    $$('.alert-toggle').forEach(c => { c.checked = enabled.has(c.dataset.type); });
    $('#settings-status').textContent =
      `effective threshold: ${s.effective_red_zone} dBm` +
      (s.baseline_office_rssi != null ? ` · baseline ${s.baseline_office_rssi} dBm` : '');
  } catch (e) { toast('Settings load failed: ' + e.message, 'error'); }
}

async function saveSettings() {
  const body = {
    rssi_red_zone:          parseInt($('#set-rssi').value, 10),
    rssi_exit_offset_db:    parseInt($('#set-hysteresis').value, 10),
    alert_timer_seconds:    parseInt($('#set-timer').value, 10),
    alert_cooldown_seconds: parseInt($('#set-cooldown').value, 10),
    dynamic_offset_db:      parseInt($('#set-offset').value, 10),
    use_dynamic_threshold:  $('#set-dynamic').checked,
    enabled_alerts:         [...$$('.alert-toggle:checked')].map(c => c.dataset.type),
  };
  try {
    const r = await api('/api/settings', { method: 'POST', body: JSON.stringify(body) });
    toast('Settings saved', 'ok');
    $('#settings-status').textContent =
      `effective threshold: ${r.effective_red_zone} dBm` +
      (r.settings.baseline_office_rssi != null ? ` · baseline ${r.settings.baseline_office_rssi} dBm` : '');
  } catch (e) { toast(e.message, 'error'); }
}

async function runSiteSurvey() {
  try {
    const r = await api('/api/setup/site_survey', { method: 'POST' });
    const lines = r.samples.map(s =>
      `  • ${s.mac} (${(s.ssids||[]).join(', ')}) — ${s.rssi} dBm`
    ).join('<br>');
    $('#survey-result').innerHTML =
      `<div class="text-emerald-700">✓ Baseline = ${r.baseline_rssi} dBm (median of ${r.samples.length} office AP samples)</div>` +
      `<div class="text-slate-500 mt-1">Effective threshold now: ${r.effective_red_zone} dBm</div>` +
      `<div class="mt-1">${lines}</div>` +
      `<div class="text-slate-500 italic mt-2">Tip: enable "Dynamic threshold" above so this baseline is actually used.</div>`;
    toast('Site survey done', 'ok');
    loadSettings();
  } catch (e) {
    $('#survey-result').innerHTML = `<div class="text-rose-600">${escapeHtml(e.message)}</div>`;
    toast(e.message, 'error');
  }
}

// ─── Ignored alerts ────────────────────────────────────────

async function refreshIgnores() {
  try {
    const rows = await api('/api/ignores');
    const tbody = $('#ignores-tbody');
    if (!tbody) return;
    if (rows.length === 0) {
      tbody.innerHTML = '';
      $('#empty-ignores').classList.remove('hidden');
      return;
    }
    $('#empty-ignores').classList.add('hidden');
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td class="px-3 py-2 text-xs">${escapeHtml(r.alert_type)}</td>
        <td class="px-3 py-2 font-mono text-xs">${escapeHtml(r.mac || '<any>')}</td>
        <td class="px-3 py-2 font-mono text-xs">${escapeHtml(r.fingerprint || '<any>')}</td>
        <td class="px-3 py-2 text-xs">${escapeHtml(r.reason || '')}</td>
        <td class="px-3 py-2 text-xs text-slate-400 font-mono">${fmtDateTime(r.created_ts)}</td>
        <td class="px-3 py-2 text-right">
          <button class="btn-rm-ignore btn btn-danger btn-sm" data-id="${r.id}">Remove</button>
        </td>
      </tr>`).join('');
  } catch (e) { /* silent */ }
}

async function addIgnore(prefill = {}) {
  const body = {
    alert_type:  prefill.alert_type || $('#ig-type').value,
    mac:         prefill.mac || $('#ig-mac').value.trim() || null,
    fingerprint: prefill.fingerprint || $('#ig-fp').value.trim() || null,
    reason:      prefill.reason || $('#ig-reason').value.trim() || '',
  };
  if (!body.mac) body.mac = null;
  if (!body.fingerprint) body.fingerprint = null;
  try {
    await api('/api/ignores', { method: 'POST', body: JSON.stringify(body) });
    toast('Ignore rule added', 'ok');
    // Drop matching alerts locally too
    state.alerts = state.alerts.filter(a => {
      const d = a.data;
      if (d.alert_type !== body.alert_type) return true;
      if (body.fingerprint && d.fingerprint !== body.fingerprint) return true;
      if (body.mac && d.mac !== body.mac) return true;
      if (!body.fingerprint && !body.mac) return false;  // global rule → drop all of this type
      return false;
    });
    renderAlerts();
    refreshIgnores();
    // Clear form
    $('#ig-mac').value = '';
    $('#ig-fp').value = '';
    $('#ig-reason').value = '';
  } catch (e) { toast(e.message, 'error'); }
}

async function removeIgnore(id) {
  try {
    await api('/api/ignores/' + id, { method: 'DELETE' });
    refreshIgnores();
    toast('Rule removed', 'ok');
  } catch (e) { toast(e.message, 'error'); }
}

async function fireTestAlert() {
  try {
    const r = await api('/api/setup/test_alert', { method: 'POST' });
    toast(`Test alert fired (count ${r.count})`, 'ok');
  } catch (e) { toast(e.message, 'error'); }
}

// ─── Monitor / Follow modal ────────────────────────────────

const monitorState = {
  fingerprint: null,
  refreshTimer: null,
};

async function openMonitor(fp, mac) {
  monitorState.fingerprint = fp;
  $('#monitor-modal').classList.remove('hidden');
  $('#monitor-body').innerHTML = '<div class="text-slate-400">Loading…</div>';
  await refreshMonitor();
  // Live refresh every 5s while open
  clearInterval(monitorState.refreshTimer);
  monitorState.refreshTimer = setInterval(refreshMonitor, 5000);
}

function closeMonitor() {
  $('#monitor-modal').classList.add('hidden');
  clearInterval(monitorState.refreshTimer);
  monitorState.refreshTimer = null;
  monitorState.fingerprint = null;
}

async function refreshMonitor() {
  const fp = monitorState.fingerprint;
  if (!fp) return;
  try {
    const r = await api('/api/history/profile/' + encodeURIComponent(fp));
    const p = r.profile || {};

    // Live status — is this fingerprint currently visible & in red zone?
    const live = state.devices.find(d => d.fingerprint === fp);
    const liveBadge = live
      ? (live.in_red_zone
          ? '<span class="px-2 py-0.5 bg-rose-100 text-rose-700 rounded text-xs">● LIVE · in red zone</span>'
          : '<span class="px-2 py-0.5 bg-emerald-100 text-emerald-700 rounded text-xs">● LIVE · out of zone</span>')
      : '<span class="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">○ not visible right now</span>';

    const visitsHtml = (r.visits || []).map(v => {
      const dur = v.exited
        ? Math.round((v.exited - v.entered)) + 's'
        : '<span class="text-emerald-600">ongoing</span>';
      return `<tr class="border-t border-gray-200">
        <td class="px-2 py-1 font-mono text-xs">${fmtDateTime(v.entered)}</td>
        <td class="px-2 py-1 font-mono text-xs">${v.exited ? fmtDateTime(v.exited) : '—'}</td>
        <td class="px-2 py-1 text-xs">${dur}</td>
        <td class="px-2 py-1 text-xs">${v.max_rssi ?? '—'} dBm</td>
      </tr>`;
    }).join('') || '<tr><td colspan="4" class="px-2 py-3 text-center text-slate-500 text-xs">No visits recorded yet.</td></tr>';

    const rssiSamples = r.rssi || [];
    const sparkline = renderSparkline(rssiSamples);

    $('#monitor-body').innerHTML = `
      <div class="flex items-center justify-between">
        <div>
          <div class="text-xs text-slate-400">Fingerprint</div>
          <div class="font-mono text-sm">${escapeHtml(fp)}</div>
        </div>
        ${liveBadge}
      </div>

      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-slate-400">First seen:</span> ${fmtDateTime(p.first_seen)}</div>
        <div><span class="text-slate-400">Last seen:</span> ${fmtDateTime(p.last_seen)}</div>
        <div><span class="text-slate-400">Vendor:</span> ${escapeHtml(p.manuf || '—')}</div>
        <div><span class="text-slate-400">Channel:</span> ${escapeHtml(p.channel || '—')}</div>
        <div><span class="text-slate-400">Avg RSSI:</span> ${p.rssi_avg?.toFixed?.(1) ?? '—'} dBm</div>
        <div><span class="text-slate-400">Currently in red zone:</span> ${p.in_red_zone ? 'yes' : 'no'}</div>
      </div>

      <div>
        <div class="text-xs text-slate-400 mb-1">Known MACs (${(r.macs || []).length}) — proves MAC rotation</div>
        <div class="font-mono text-xs text-slate-300 break-all">${(r.macs || []).map(escapeHtml).join(', ') || '—'}</div>
      </div>

      <div>
        <div class="text-xs text-slate-400 mb-1">Probed SSIDs</div>
        <div class="text-xs text-slate-300">${(JSON.parse(p.probed_ssids || '[]')).map(escapeHtml).join(', ') || '<span class="text-slate-600">none</span>'}</div>
      </div>

      <div>
        <div class="text-xs text-slate-400 mb-1">RSSI history (last ${rssiSamples.length} samples)</div>
        ${sparkline}
      </div>

      <div>
        <div class="text-xs text-slate-400 mb-1">Visit timeline — each red-zone entry/exit</div>
        <div class="overflow-x-auto border border-gray-200 rounded">
          <table class="w-full text-sm">
            <thead class="bg-gray-100 text-gray-500 text-xs uppercase">
              <tr>
                <th class="text-left px-2 py-1">Entered</th>
                <th class="text-left px-2 py-1">Exited</th>
                <th class="text-left px-2 py-1">Duration</th>
                <th class="text-left px-2 py-1">Max RSSI</th>
              </tr>
            </thead>
            <tbody>${visitsHtml}</tbody>
          </table>
        </div>
      </div>

      <div class="text-xs text-slate-500 italic">Refreshing every 5 seconds while open.</div>
    `;
  } catch (e) {
    $('#monitor-body').innerHTML = `<div class="text-rose-600">Failed to load: ${escapeHtml(e.message)}</div>`;
  }
}

function renderSparkline(samples) {
  if (!samples || samples.length === 0) return '<span class="text-slate-600 text-xs">no samples</span>';
  const vals = samples.map(s => s.rssi);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const range = max - min || 1;
  const W = 400, H = 40;
  const step = W / Math.max(1, samples.length - 1);
  const pts = vals.map((v, i) =>
    `${(i * step).toFixed(1)},${(H - ((v - min) / range) * H).toFixed(1)}`
  ).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" class="w-full h-10 bg-slate-950 rounded border border-slate-800">
    <polyline points="${pts}" fill="none" stroke="rgb(96,165,250)" stroke-width="1.5"/>
  </svg>
  <div class="text-xs text-slate-500">min ${min} dBm · max ${max} dBm</div>`;
}

// Load historical alerts from SQLite (survives restarts)
async function refreshAlertsHistory() {
  try {
    const rows = await api('/api/history/alerts?limit=200');
    // Dedup by (fingerprint, alert_type) — newer wins
    const merged = new Map();
    const key = (fp, t) => `${fp || ''}|${t}`;

    for (const a of state.alerts) {
      merged.set(key(a.data.fingerprint, a.data.alert_type), a);
    }
    for (const r of rows) {
      const k = key(r.fingerprint, r.alert_type);
      const evt = {
        type: 'alert',
        ts:   r.ts,
        data: {
          alert_type:      r.alert_type,
          mac:             r.mac,
          fingerprint:     r.fingerprint,
          rssi_avg:        r.rssi_avg,
          spoofed_ssid:    r.spoofed_ssid || '',
          spoof_reason:    r.spoof_reason || '',
          seconds_present: r.seconds_present || 0,
          probed_ssids:    r.probed_ssids ? JSON.parse(r.probed_ssids) : [],
          advertised_ssids: r.advertised_ssids ? JSON.parse(r.advertised_ssids) : [],
          device_type:     r.device_type || '',
          manuf:           r.manuf || '',
          channel:         r.channel || '',
          count:           r.count || 1,
          first_ts:        r.first_ts || r.ts,
        },
      };
      const existing = merged.get(k);
      if (!existing || existing.ts < evt.ts) merged.set(k, evt);
    }
    state.alerts = [...merged.values()].sort((a, b) => a.ts - b.ts);
    renderAlerts();
  } catch (e) { /* silent */ }
}

// ─── setup tab ─────────────────────────────────────────────

async function refreshSetupAPs() {
  try {
    const aps = await api('/api/setup/visible_aps');
    const wl  = await api('/api/whitelist');
    const known = new Set((wl.infrastructure || []).map(i => i.mac.toUpperCase()));

    const tbody = $('#setup-ap-tbody');
    $('#setup-ap-count').textContent = `${aps.length} AP(s) visible`;

    if (aps.length === 0) {
      tbody.innerHTML = '';
      $('#setup-empty').classList.remove('hidden');
      return;
    }
    $('#setup-empty').classList.add('hidden');

    tbody.innerHTML = aps.map(ap => {
      const isKnown = known.has(ap.mac.toUpperCase());
      const ssids   = (ap.advertised_ssids || []).map(escapeHtml).join(', ') || '<span class="text-slate-600">—</span>';
      const status  = isKnown
        ? '<span class="text-emerald-600 text-xs">✓ already safe</span>'
        : '<span class="text-slate-500 text-xs">unknown</span>';
      return `<tr>
        <td class="px-3 py-2 text-center">
          <input type="checkbox" class="ap-pick" data-mac="${escapeHtml(ap.mac)}" ${isKnown ? 'disabled' : ''} />
        </td>
        <td class="px-3 py-2 font-mono text-xs">${escapeHtml(ap.mac)}</td>
        <td class="px-3 py-2 text-xs">${ssids}</td>
        <td class="px-3 py-2 text-xs">${escapeHtml(ap.channel || '—')}</td>
        <td class="px-3 py-2 text-xs text-slate-400">${escapeHtml(ap.manuf || '')}</td>
        <td class="px-3 py-2 text-right">${rssiBar(ap.rssi_avg ?? ap.rssi)}</td>
        <td class="px-3 py-2">${status}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    toast('Setup load failed: ' + e.message, 'error');
  }
}

async function markSelectedSafeAPs() {
  const macs = [...$$('#setup-ap-tbody .ap-pick:checked')].map(c => c.dataset.mac);
  if (macs.length === 0) {
    toast('Select at least one AP', 'error');
    return;
  }
  try {
    const r = await api('/api/setup/mark_safe_aps', {
      method: 'POST',
      body: JSON.stringify({ macs }),
    });
    toast(`Added ${r.added} office AP(s)`, 'ok');
    refreshSetupAPs();
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function rescanClients() {
  const btn = $('#btn-rescan');
  btn.disabled = true;
  btn.textContent = '… scanning';
  try {
    const r = await api('/api/setup/rescan_clients', { method: 'POST' });
    $('#rescan-result').innerHTML =
      `<div class="text-emerald-700">✓ ${r.added} new employee device(s) added</div>` +
      `<div class="text-slate-500 text-xs mt-1">` +
        `${r.already_safe} already whitelisted · ` +
        `${r.not_seen} associated but not yet seen by our scan · ` +
        `${r.total_associated} total clients associated to office APs` +
      `</div>`;
    toast(`Rescan done: +${r.added}`, 'ok');
  } catch (e) {
    $('#rescan-result').innerHTML = `<div class="text-rose-600">${escapeHtml(e.message)}</div>`;
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '⟳ Rescan & whitelist connected clients';
  }
}

// ─── API calls ─────────────────────────────────────────────

async function api(path, opts={}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(err.detail || r.statusText);
  }
  return r.json();
}

async function refreshWhitelist() {
  try {
    const data = await api('/api/whitelist');
    renderWhitelist(data);
  } catch (e) { toast('Whitelist load failed: ' + e.message, 'error'); }
}

// ─── WebSocket ─────────────────────────────────────────────

function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws = ws;
  ws.onopen  = () => setWsStatus(true);
  ws.onclose = () => { setWsStatus(false); setTimeout(connectWs, 2000); };
  ws.onerror = () => setWsStatus(false);
  ws.onmessage = (e) => {
    let msg; try { msg = JSON.parse(e.data); } catch { return; }
    handleEvent(msg);
  };
}

function handleEvent(msg) {
  switch (msg.type) {
    case 'snapshot':
      state.devices = msg.devices || [];
      state.alerts  = msg.alerts  || [];
      setStatus(msg.stats?.running);
      renderDevices();
      renderAlerts();
      renderAlertsCounter();
      refreshAlertsHistory();   // pull persisted alerts on first load
      break;
    case 'cycle':
      state.devices = msg.devices || [];
      setStatus(msg.stats?.running);
      if (state.tab === 'devices')  renderDevices();
      if (state.tab === 'suspects') renderSuspects();
      break;
    case 'alert': {
      const fp   = msg.data.fingerprint || msg.data.mac;
      const type = msg.data.alert_type;
      const idx  = state.alerts.findIndex(a =>
        (a.data.fingerprint || a.data.mac) === fp && a.data.alert_type === type
      );
      if (idx >= 0) {
        // Same fingerprint+type: refresh in place (bump timestamp, keep one row)
        state.alerts[idx] = msg;
      } else {
        state.alerts.push(msg);
        if (state.alerts.length > 200) state.alerts.shift();
      }
      if (state.tab === 'alerts') renderAlerts();
      renderAlertsCounter();
      const cnt = msg.data.count > 1 ? ` (×${msg.data.count})` : '';
      toast(`🚨 ${type} — ${msg.data.mac}${cnt}`, 'error');
      break;
    }
    case 'status':
      setStatus(msg.running);
      break;
    case 'error':
      toast('Engine error: ' + msg.message, 'error');
      break;
  }
}

// ─── event wiring ──────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  showView(viewFromUrl());
  window.addEventListener('popstate', () => showView(viewFromUrl()));

  // mark the default filter active
  $$('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === state.filter));
  $$('.filter-btn').forEach(b => b.addEventListener('click', () => {
    state.filter = b.dataset.filter;
    $$('.filter-btn').forEach(x => x.classList.toggle('active', x === b));
    renderDevices();
  }));
  $('#search').addEventListener('input', e => {
    state.search = e.target.value;
    renderDevices();
  });

  $('#btn-reload-aps').addEventListener('click', refreshSetupAPs);
  $('#btn-mark-safe' ).addEventListener('click', markSelectedSafeAPs);
  $('#btn-rescan'    ).addEventListener('click', rescanClients);
  $('#btn-save-settings')?.addEventListener('click', saveSettings);
  $('#btn-site-survey' )?.addEventListener('click', runSiteSurvey);
  $('#btn-test-alert'  )?.addEventListener('click', fireTestAlert);
  $('#btn-add-ignore'  )?.addEventListener('click', () => addIgnore());
  $('#ap-select-all').addEventListener('change', e => {
    $$('#setup-ap-tbody .ap-pick:not(:disabled)').forEach(c => { c.checked = e.target.checked; });
  });

  $('#filter-stable')?.addEventListener('change', e => {
    state.suspectsStableOnly = e.target.checked;
    renderSuspects();
  });
  $('#filter-identified')?.addEventListener('change', e => {
    state.suspectsHideUnknown = e.target.checked;
    renderSuspects();
  });
  $('#filter-rssi')?.addEventListener('change', e => {
    state.suspectsRssi = parseInt(e.target.value, 10);
    renderSuspects();
  });

  // Monitor modal
  $('#monitor-close').addEventListener('click', closeMonitor);
  $('#monitor-modal').addEventListener('click', (e) => {
    if (e.target.id === 'monitor-modal') closeMonitor();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMonitor();
  });

  // event delegation for dynamic buttons
  document.addEventListener('click', async (e) => {
    const t = e.target;
    try {
      if (t.classList.contains('btn-monitor')) {
        openMonitor(t.dataset.fp, t.dataset.mac);
        return;
      }
      if (t.classList.contains('btn-ignore')) {
        const reason = prompt('Reason (optional):', '') || '';
        addIgnore({
          alert_type:  t.dataset.type,
          fingerprint: t.dataset.fp || null,
          mac:         t.dataset.mac || null,
          reason,
        });
        return;
      }
      if (t.classList.contains('btn-rm-ignore')) {
        removeIgnore(t.dataset.id);
        return;
      }
      if (t.classList.contains('btn-emp')) {
        const r = await api('/api/whitelist/employee', {
          method: 'POST', body: JSON.stringify({ mac: t.dataset.mac })
        });
        toast('Added employee: ' + r.fingerprint, 'ok');
        if (state.tab === 'whitelist') refreshWhitelist();
      } else if (t.classList.contains('btn-infra')) {
        const label = prompt('Label (optional):', '') || '';
        await api('/api/whitelist/infra', {
          method: 'POST', body: JSON.stringify({ mac: t.dataset.mac, label })
        });
        toast('Added Known AP', 'ok');
        if (state.tab === 'whitelist') refreshWhitelist();
      } else if (t.classList.contains('btn-rm-emp')) {
        await api('/api/whitelist/employee/' + encodeURIComponent(t.dataset.fp), { method: 'DELETE' });
        toast('Removed', 'ok');
        refreshWhitelist();
      } else if (t.classList.contains('btn-rm-infra')) {
        await api('/api/whitelist/infra/' + encodeURIComponent(t.dataset.mac), { method: 'DELETE' });
        toast('Removed', 'ok');
        refreshWhitelist();
      }
    } catch (err) { toast(err.message, 'error'); }
  });

  connectWs();
  api('/api/settings').then(s => { state.alertTimer = s.alert_timer_seconds || 60; }).catch(() => {});
});
