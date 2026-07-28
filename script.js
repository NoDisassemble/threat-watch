const API_BASE = '/api/v1';
let cweRecords = [];
let cveRecords = [];

const themeButton = document.querySelector('.theme-toggle');
function setTheme(theme) {
  const isDark = theme === 'dark';
  document.documentElement.dataset.theme = theme;
  themeButton.setAttribute('aria-pressed', String(isDark));
  themeButton.setAttribute('aria-label', `Switch to ${isDark ? 'light' : 'dark'} theme`);
  themeButton.querySelector('.theme-label').textContent = isDark ? 'Light' : 'Dark';
}
setTheme(localStorage.getItem('theme') || 'dark');
themeButton.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  setTheme(next);
  localStorage.setItem('theme', next);
});

function showView(route, updateHistory = true) {
  const target = document.getElementById(route) || document.getElementById('cwe-watchlist');
  document.querySelectorAll('.view-panel').forEach((panel) => panel.classList.toggle('active', panel === target));
  document.querySelectorAll('[data-route]').forEach((link) => link.classList.toggle('active', link.dataset.route === target.id));
  document.querySelector('#topbar-context').textContent = target.dataset.title;
  document.body.classList.remove('nav-open');
  document.querySelector('.menu-toggle').setAttribute('aria-expanded', 'false');
  if (updateHistory) history.replaceState(null, '', `#${target.id}`);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
document.querySelectorAll('[data-route]').forEach((link) => link.addEventListener('click', (event) => {
  event.preventDefault();
  showView(link.dataset.route);
}));
document.querySelector('.menu-toggle').addEventListener('click', (event) => {
  const open = document.body.classList.toggle('nav-open');
  event.currentTarget.setAttribute('aria-expanded', String(open));
});
showView(location.hash.slice(1) || 'cwe-watchlist', false);

async function get(path) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    const error = new Error(`API returned ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}
async function getLocal(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Watchlist returned ${response.status}`);
  return response.json();
}
function cleanText(value = '') { return String(value).replace(/\s+/g, ' ').trim(); }
function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[character]));
}
function formatDate(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function renderCweCards(items) {
  document.querySelector('#weakness-grid').innerHTML = items.map((item, index) => {
    const description = cleanText(item.Description || 'No description available.');
    const detailId = `cwe-${item.ID}-description`;
    const mappings = (item.owasp || []).map((category) => `<a class="data-badge" href="${escapeHtml(category.url)}" target="_blank" rel="noreferrer">OWASP ${escapeHtml(category.code)} · #${category.rank}</a>`).join('');
    return `<article class="weakness-card ranked-card">
      <div class="rank-number">0${index + 1}</div>
      <header><span>CWE-${escapeHtml(item.ID)}</span><span class="status">Score ${item.threat_score}</span></header>
      <div class="badge-row">${mappings || '<span class="data-badge muted-badge">No OWASP Top 10 mapping</span>'}</div>
      <h3>${escapeHtml(item.Name || 'Unnamed weakness')}</h3><p>${escapeHtml(description.slice(0, 180))}${description.length > 180 ? '…' : ''}</p>
      ${description.length > 180 ? `<button class="desc-toggle" type="button" aria-expanded="false" aria-controls="${detailId}">Full description <span>↓</span></button><p class="full-description" id="${detailId}" hidden>${escapeHtml(description)}</p>` : ''}
      <footer>${item.kev_count} KEVs · ${item.ransomware_count} ransomware · EPSS ${item.epss_percentile}%</footer>
    </article>`;
  }).join('');
}

function renderCveCards(items) {
  document.querySelector('#cve-grid').innerHTML = items.map((item, index) => {
    const description = cleanText(item.description || item.short_description || item.required_action || 'No description available.');
    const cwes = (item.cwes || []).map((cwe) => `<span class="data-badge">${escapeHtml(cwe)}</span>`).join('');
    return `<article class="weakness-card ranked-card cve-card">
      <div class="rank-number">0${index + 1}</div>
      <header><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}" target="_blank" rel="noreferrer">${escapeHtml(item.id)} ↗</a><span class="status">Score ${item.threat_score}</span></header>
      <div class="badge-row"><span class="data-badge kev-badge">Actively exploited</span>${item.ransomware ? '<span class="data-badge danger-badge">Ransomware</span>' : ''}${item.cvss_severity ? `<span class="data-badge">CVSS ${escapeHtml(item.cvss_severity)}</span>` : ''}${cwes}</div>
      <p class="product-line">${escapeHtml(item.vendor)} / ${escapeHtml(item.product)}</p>
      <h3>${escapeHtml(item.name || item.id)}</h3><p>${escapeHtml(description.slice(0, 200))}${description.length > 200 ? '…' : ''}</p>
      <footer>EPSS ${item.epss_probability}% · CVSS ${item.cvss_score || 'N/A'} · Added ${formatDate(item.date_added)}</footer>
    </article>`;
  }).join('');
}

function barRows(items, value, label, maxValue = null) {
  const maximum = maxValue || Math.max(...items.map(value), 1);
  return items.map((item) => {
    const amount = Number(value(item)) || 0;
    const width = Math.max(2, Math.min(100, amount / maximum * 100));
    return `<div class="bar-row"><div class="bar-label"><span>${escapeHtml(label(item))}</span><strong>${amount}</strong></div><div class="bar-track"><span style="width:${width}%"></span></div></div>`;
  }).join('');
}

const lineColors = ['#ff5c35', '#1f8a70', '#7c5cff', '#d49b00', '#3273dc'];

function formatMonth(month) {
  const [year, monthNumber] = month.split('-').map(Number);
  return new Intl.DateTimeFormat('en-US', { month: 'short', year: '2-digit', timeZone: 'UTC' })
    .format(new Date(Date.UTC(year, monthNumber - 1, 1)));
}

function lineChart(series, ariaLabel, yAxisLabel = 'Cumulative KEV count', xAxisLabel = 'Catalog addition month') {
  const validSeries = series.filter((item) => item.points?.length);
  if (!validSeries.length) return '<p class="chart-empty">Timeline data is unavailable.</p>';

  const width = 720;
  const height = 300;
  const plot = { left: 68, right: 18, top: 18, bottom: 62 };
  const points = validSeries[0].points;
  const maxValue = Math.max(1, ...validSeries.flatMap((item) => item.points.map((point) => Number(point.count) || 0)));
  const niceMax = Math.ceil(maxValue / Math.max(1, Math.pow(10, Math.floor(Math.log10(maxValue))))) * Math.max(1, Math.pow(10, Math.floor(Math.log10(maxValue))));
  const x = (index) => plot.left + index * (width - plot.left - plot.right) / Math.max(1, points.length - 1);
  const y = (value) => plot.top + (niceMax - value) * (height - plot.top - plot.bottom) / niceMax;
  const ticks = [0, .25, .5, .75, 1];
  const labelIndexes = [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])];

  const grid = ticks.map((tick) => {
    const value = Math.round(niceMax * tick);
    return `<g><line class="line-grid" x1="${plot.left}" y1="${y(value)}" x2="${width - plot.right}" y2="${y(value)}"></line><text class="line-axis-label" x="${plot.left - 10}" y="${y(value) + 4}" text-anchor="end">${value}</text></g>`;
  }).join('');
  const xLabels = labelIndexes.map((index) => `<text class="line-axis-label" x="${x(index)}" y="${height - 32}" text-anchor="middle">${formatMonth(points[index].month)}</text>`).join('');
  const plotMiddleY = (plot.top + height - plot.bottom) / 2;
  const axisTitles = `<text class="line-axis-title" x="${(plot.left + width - plot.right) / 2}" y="${height - 6}" text-anchor="middle">${escapeHtml(xAxisLabel)}</text><text class="line-axis-title" x="14" y="${plotMiddleY}" text-anchor="middle" transform="rotate(-90 14 ${plotMiddleY})">${escapeHtml(yAxisLabel)}</text>`;
  const paths = validSeries.map((item, seriesIndex) => {
    const color = lineColors[seriesIndex % lineColors.length];
    const path = item.points.map((point, index) => `${index ? 'L' : 'M'} ${x(index).toFixed(1)} ${y(Number(point.count) || 0).toFixed(1)}`).join(' ');
    const markers = item.points.map((point, index) => `<circle cx="${x(index)}" cy="${y(Number(point.count) || 0)}" r="3" fill="${color}"><title>${escapeHtml(item.label)} · ${formatMonth(point.month)}: ${Number(point.count).toLocaleString()}</title></circle>`).join('');
    return `<g><path class="line-series" d="${path}" stroke="${color}"></path>${markers}</g>`;
  }).join('');
  const legend = validSeries.map((item, index) => `<span><i style="--series-color:${lineColors[index % lineColors.length]}"></i>${escapeHtml(item.label)}</span>`).join('');

  return `<div class="line-chart"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(ariaLabel)}">${grid}${xLabels}${axisTitles}${paths}</svg><div class="line-legend">${legend}</div></div>`;
}

function renderCweCharts(items, timeline = []) {
  const timelineSeries = timeline.map((item) => ({ label: item.id, points: item.points }));
  document.querySelector('#cwe-chart-grid').innerHTML = `
    <article class="chart-card chart-wide"><p class="eyebrow">Exploited over time</p><h3>Cumulative KEV additions by weakness</h3><p class="chart-note">Cumulative vulnerabilities in CISA's KEV catalog, grouped by the current top CWEs. Dates reflect catalog additions.</p>${lineChart(timelineSeries, 'Cumulative CISA KEV additions over the last 12 months by CWE')}</article>
    <article class="chart-card chart-wide"><p class="eyebrow">Composite ranking</p><h3>Threat score</h3>${barRows(items, (x) => x.threat_score, (x) => `CWE-${x.ID}`, 100)}</article>
    <article class="chart-card"><p class="eyebrow">Observed exploitation</p><h3>KEV volume</h3>${barRows(items, (x) => x.kev_count, (x) => `CWE-${x.ID}`)}</article>
    <article class="chart-card"><p class="eyebrow">Exploit likelihood</p><h3>EPSS percentile</h3>${barRows(items, (x) => x.epss_percentile, (x) => `CWE-${x.ID}`, 100)}</article>`;
}
function renderCveCharts(items, timeline = []) {
  document.querySelector('#cve-chart-grid').innerHTML = `
    <article class="chart-card chart-wide"><p class="eyebrow">Exploited over time</p><h3>Cumulative KEV additions</h3><p class="chart-note">Cumulative vulnerabilities added to CISA's KEV catalog within the current 365-day candidate window.</p>${lineChart([{ label: 'All CVE candidates', points: timeline }], 'Cumulative CISA KEV additions in the current CVE candidate window')}</article>
    <article class="chart-card chart-wide"><p class="eyebrow">Composite ranking</p><h3>Threat score</h3>${barRows(items, (x) => x.threat_score, (x) => x.id, 100)}</article>
    <article class="chart-card"><p class="eyebrow">30-day probability</p><h3>EPSS probability</h3>${barRows(items, (x) => x.epss_probability, (x) => x.id, 100)}</article>
    <article class="chart-card"><p class="eyebrow">Technical severity</p><h3>CVSS base score</h3>${barRows(items, (x) => x.cvss_score || 0, (x) => x.id, 10)}</article>`;
}

async function loadCweDashboard() {
  document.querySelector('#weakness-grid').innerHTML = '<p class="loading">Loading live CWE records…</p>';
  try {
    const watchlist = await getLocal('/api/watchlist');
    if (!watchlist.items?.length) throw new Error(watchlist.error || 'No threat-ranked CWEs were returned.');
    const ids = watchlist.items.map((item) => item.id).join(',');
    document.querySelector('#content-version').textContent = 'Unavailable';
    document.querySelector('#content-date').textContent = 'Loading MITRE catalog metadata…';
    document.querySelector('#weakness-count').textContent = '—';
    document.querySelector('#category-count').textContent = '—';
    document.querySelector('#view-count').textContent = '—';
    cweRecords = watchlist.items.map((rank) => ({
      ID: rank.id,
      Name: `CWE-${rank.id}`,
      Description: 'Detailed weakness metadata is temporarily unavailable from the MITRE CWE API.',
      ...rank,
    })).sort((a, b) => b.threat_score - a.threat_score);
    document.querySelector('#download-report').disabled = false;
    renderCweCards(cweRecords);
    renderCweCharts(cweRecords, watchlist.exploitation_timeline);

    const [versionResult, weaknessResult] = await Promise.allSettled([
      get('/cwe/version'),
      get(`/cwe/weakness/${ids}`),
    ]);
    const version = versionResult.status === 'fulfilled' ? versionResult.value : null;
    const weaknesses = weaknessResult.status === 'fulfilled' ? weaknessResult.value.Weaknesses || [] : [];

    document.querySelector('#content-version').textContent = version?.ContentVersion ? `v${version.ContentVersion}` : 'Unavailable';
    document.querySelector('#content-date').textContent = version?.ContentDate ? `Released ${version.ContentDate.trim()}` : 'MITRE API temporarily unavailable';
    document.querySelector('#weakness-count').textContent = version ? Number(version.TotalWeaknesses || 0).toLocaleString() : '—';
    document.querySelector('#category-count').textContent = version ? Number(version.TotalCategories || 0).toLocaleString() : '—';
    document.querySelector('#view-count').textContent = version ? Number(version.TotalViews || 0).toLocaleString() : '—';
    const details = new Map(weaknesses.map((item) => [String(item.ID), item]));
    cweRecords = watchlist.items.map((rank) => ({
      ID: rank.id,
      Name: `CWE-${rank.id}`,
      Description: 'Detailed weakness metadata is temporarily unavailable from the MITRE CWE API.',
      ...details.get(String(rank.id)),
      ...rank,
    })).sort((a, b) => b.threat_score - a.threat_score);
    renderCweCards(cweRecords);
  } catch (error) {
    cweRecords = [];
    document.querySelector('#download-report').disabled = true;
    document.querySelector('#weakness-grid').innerHTML = `<p class="loading error">Unable to load live CWE data. ${escapeHtml(error.message)}</p>`;
    document.querySelector('#cwe-chart-grid').innerHTML = '<p class="loading error">CWE charts are unavailable.</p>';
  }
}

async function loadCveDashboard() {
  document.querySelector('#cve-grid').innerHTML = '<p class="loading">Loading live CVE records…</p>';
  try {
    const watchlist = await getLocal('/api/cve-watchlist');
    if (!watchlist.items?.length) throw new Error(watchlist.error || 'No threat-ranked CVEs were returned.');
    cveRecords = watchlist.items;
    document.querySelector('#cve-window').textContent = `${watchlist.window_days}d`;
    document.querySelector('#cve-candidate-count').textContent = Number(watchlist.candidate_count || 0).toLocaleString();
    document.querySelector('#cve-ransomware-count').textContent = cveRecords.filter((item) => item.ransomware).length;
    document.querySelector('#cve-catalog-date').textContent = formatDate(watchlist.catalog_date);
    renderCveCards(cveRecords);
    renderCveCharts(cveRecords, watchlist.exploitation_timeline);
  } catch (error) {
    cveRecords = [];
    document.querySelector('#cve-grid').innerHTML = `<p class="loading error">Unable to load live CVE data. ${escapeHtml(error.message)}</p>`;
    document.querySelector('#cve-chart-grid').innerHTML = '<p class="loading error">CVE charts are unavailable.</p>';
  }
}

function renderRecord(result, eyebrow, title, description, metadata = [], links = []) {
  result.hidden = false;
  result.innerHTML = `<p class="eyebrow">${escapeHtml(eyebrow)}</p><h3>${escapeHtml(title)}</h3><p>${escapeHtml(cleanText(description))}</p><div class="record-meta">${metadata.map((item) => `<span>${escapeHtml(item)}</span>`).join('')}</div>${links.length ? `<div class="record-links">${links.map((link) => `<a href="${escapeHtml(link)}" target="_blank" rel="noreferrer">Source ↗</a>`).join('')}</div>` : ''}`;
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

document.querySelector('#lookup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = document.querySelector('#cwe-id').value.replace(/^CWE-/i, '').trim();
  const result = document.querySelector('#record-result');
  result.hidden = false;
  result.innerHTML = '<p class="loading">Fetching CWE record…</p>';
  try {
    const data = await get(`/cwe/weakness/${encodeURIComponent(id)}`);
    const item = data.Weaknesses?.[0];
    if (!item) throw Object.assign(new Error('Not found'), { status: 404 });
    renderRecord(result, `CWE-${item.ID} record`, item.Name || 'Unnamed weakness', item.Description || item.ExtendedDescription || 'No description returned.', [item.Status || 'Status unavailable', item.Abstraction || 'Type unavailable', item.LikelihoodOfExploit ? `Exploit likelihood: ${item.LikelihoodOfExploit}` : '']);
  } catch (error) {
    result.innerHTML = error.status === 404 ? `<p class="error">No record was found for CWE-${escapeHtml(id)}.</p>` : '<p class="error">Unable to look up this CWE right now.</p>';
  }
});

document.querySelector('#cve-lookup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  let id = document.querySelector('#cve-id').value.trim().toUpperCase();
  if (!id.startsWith('CVE-')) id = `CVE-${id}`;
  const result = document.querySelector('#cve-record-result');
  result.hidden = false;
  result.innerHTML = '<p class="loading">Fetching CVE record…</p>';
  try {
    const item = await getLocal(`/api/cve/${encodeURIComponent(id)}`);
    if (!item.id) throw Object.assign(new Error('Not found'), { status: 404 });
    renderRecord(result, `${item.id} record`, item.id, item.description || 'No English description returned.', [item.status || 'Status unavailable', item.cvss_score ? `CVSS ${item.cvss_score} ${item.cvss_severity || ''}` : 'CVSS unavailable', ...(item.cwes || [])], item.references || []);
  } catch (error) {
    result.innerHTML = error.status === 404 ? `<p class="error">No NVD record was found for ${escapeHtml(id)}.</p>` : '<p class="error">Unable to look up this CVE right now.</p>';
  }
});

document.querySelectorAll('.example-id').forEach((button) => button.addEventListener('click', () => {
  document.querySelector('#cwe-id').value = button.dataset.id;
  document.querySelector('#lookup-form').requestSubmit();
}));
document.querySelectorAll('.refresh-data').forEach((button) => button.addEventListener('click', () => {
  button.textContent = 'Refreshing…';
  Promise.all([loadCweDashboard(), loadCveDashboard()]).finally(() => { button.textContent = 'Refresh data ↻'; });
}));
document.querySelector('#weakness-grid').addEventListener('click', (event) => {
  const button = event.target.closest('.desc-toggle');
  if (!button) return;
  const description = document.getElementById(button.getAttribute('aria-controls'));
  const expanded = button.getAttribute('aria-expanded') === 'true';
  button.setAttribute('aria-expanded', String(!expanded));
  button.innerHTML = `${expanded ? 'Full description <span>↓</span>' : 'Collapse description <span>↑</span>'}`;
  description.hidden = expanded;
});

document.querySelector('#download-report').addEventListener('click', () => {
  if (!cweRecords.length || !window.jspdf?.jsPDF) return;
  const { jsPDF } = window.jspdf;
  const pdf = new jsPDF({ unit: 'pt', format: 'a4' });
  let y = 55;
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(20);
  pdf.text('THREAT WATCH — CWE TOP 5', 50, y);
  y += 35;
  cweRecords.forEach((item, index) => {
    pdf.setFontSize(13);
    pdf.text(`${index + 1}. CWE-${item.ID}: ${item.Name}`, 50, y);
    y += 18;
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.text(`Score ${item.threat_score} | KEVs ${item.kev_count} | Ransomware ${item.ransomware_count} | EPSS ${item.epss_percentile}%`, 50, y);
    y += 20;
    const lines = pdf.splitTextToSize(cleanText(item.Description || 'No description returned.'), 495);
    pdf.text(lines, 50, y);
    y += lines.length * 11 + 24;
    pdf.setFont('helvetica', 'bold');
  });
  pdf.save(`threat-watch-cwe-top-5-${new Date().toISOString().slice(0, 10)}.pdf`);
});

Promise.all([loadCweDashboard(), loadCveDashboard()]);
