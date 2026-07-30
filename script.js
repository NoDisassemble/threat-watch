const API_BASE = '/api/v1';
let cweRecords = [];
let cveRecords = [];
const overviewState = { cwe: null, cve: null, dshield: null, ransomware: null };

async function loadAppVersion() {
  try {
    const response = await fetch('/api/version');
    if (!response.ok) return;
    const data = await response.json();
    document.querySelector('#app-version').textContent = `v${String(data.version).replace(/^v/i, '')}`;
  } catch (_) {
    // Keep the version embedded in the page when the API is unavailable.
  }
}
loadAppVersion();

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
  const target = document.getElementById(route) || document.getElementById('overview');
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
showView(location.hash.slice(1) || 'overview', false);

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
function formatDateTime(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}
function number(value) { return Number(value || 0).toLocaleString(); }
function displayGroupName(value) {
  return cleanText(value).replace(/\b[a-z]/g, (character) => character.toUpperCase());
}

function renderCweCards(items) {
  document.querySelector('#weakness-grid').innerHTML = items.map((item, index) => {
    const description = cleanText(item.Description || 'No description available.');
    const detailId = `cwe-${item.ID}-description`;
    const mappings = (item.owasp || []).map((category) => `<a class="data-badge" href="${escapeHtml(category.url)}" target="_blank" rel="noreferrer">OWASP ${escapeHtml(category.code)} · #${category.rank}</a>`).join('');
    return `<article class="weakness-card ranked-card">
      <div class="rank-number">${String(index + 1).padStart(2, '0')}</div>
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
      <div class="rank-number">${String(index + 1).padStart(2, '0')}</div>
      <header><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}" target="_blank" rel="noreferrer">${escapeHtml(item.id)} ↗</a><span class="status">Score ${item.threat_score}</span></header>
      <div class="badge-row"><span class="data-badge kev-badge">Actively exploited</span>${item.ransomware ? '<span class="data-badge danger-badge">Ransomware</span>' : ''}${item.cvss_severity ? `<span class="data-badge">CVSS ${escapeHtml(item.cvss_severity)}</span>` : ''}${cwes}</div>
      <p class="product-line">${escapeHtml(item.vendor)} / ${escapeHtml(item.product)}</p>
      <h3>${escapeHtml(item.name || item.id)}</h3><p>${escapeHtml(description.slice(0, 200))}${description.length > 200 ? '…' : ''}</p>
      <footer>EPSS ${item.epss_probability}% · CVSS ${item.cvss_score || 'N/A'} · Added ${formatDate(item.date_added)}</footer>
    </article>`;
  }).join('');
}

function renderRansomwareCards(items) {
  document.querySelector('#ransomware-grid').innerHTML = items.map((item, index) => {
    const momentum = Number(item.recent_7d_count || 0) - Number(item.previous_7d_count || 0);
    const claims = (item.recent_victims || []).map((claim) => `<li><span>${escapeHtml(claim.title)}</span><time datetime="${escapeHtml(claim.discovered)}">${formatDate(claim.discovered)}</time></li>`).join('');
    return `<article class="weakness-card ranked-card ransomware-card">
      <div class="rank-number">${String(index + 1).padStart(2, '0')}</div>
      <header><span>RansomLook activity</span><span class="status">${number(item.share_percentage)}% share</span></header>
      <div class="badge-row"><span class="data-badge danger-badge">${number(item.recent_7d_count)} claims · 7d</span><span class="data-badge ${momentum > 0 ? 'kev-badge' : 'muted-badge'}">Momentum ${momentum > 0 ? '+' : ''}${number(momentum)}</span></div>
      <h3>${escapeHtml(displayGroupName(item.name))}</h3>
      <p>Most recently observed public victim claims:</p>
      ${claims ? `<ul class="claim-list">${claims}</ul>` : '<p class="chart-empty">No recent claim titles were returned.</p>'}
      <footer>${number(item.claim_count)} claims in 30 days · Last seen ${formatDateTime(item.last_seen)}</footer>
    </article>`;
  }).join('');
}

function barRows(items, value, label, maxValue = null) {
  const maximum = maxValue || Math.max(...items.map(value), 1);
  return items.map((item) => {
    const amount = Number(value(item)) || 0;
    const width = Math.max(2, Math.min(100, amount / maximum * 100));
    return `<div class="bar-row"><div class="bar-label"><span>${escapeHtml(label(item))}</span><strong>${amount.toLocaleString()}</strong></div><div class="bar-track"><span style="width:${width}%"></span></div></div>`;
  }).join('');
}

function overviewCard({ domain, status, title, summary, stats, chartTitle, chart, route }) {
  return `<article class="overview-card" data-route="${escapeHtml(route)}" role="link" tabindex="0" aria-label="Open ${escapeHtml(domain)} intelligence">
    <div class="overview-data">
      <div class="overview-domain"><p class="eyebrow"><span class="live-dot"></span>${escapeHtml(domain)}</p><span class="status">${escapeHtml(status)}</span></div>
      <h2>${escapeHtml(title)}</h2>
      <p class="overview-summary">${escapeHtml(summary)}</p>
      <div class="overview-stats">${stats.map((item) => `<div class="overview-stat"><strong>${escapeHtml(item.value)}</strong><span>${escapeHtml(item.label)}</span></div>`).join('')}</div>
      <a class="overview-link" href="#${escapeHtml(route)}" data-route="${escapeHtml(route)}">Open ${escapeHtml(domain)} intelligence →</a>
    </div>
    <div class="overview-chart"><p class="eyebrow">Current snapshot</p><h3>${escapeHtml(chartTitle)}</h3>${chart}</div>
  </article>`;
}

function overviewPlaceholder(domain, message = 'Loading live snapshot…') {
  return `<article class="overview-card overview-loading"><p class="loading"><strong>${escapeHtml(domain)}</strong><br />${escapeHtml(message)}</p></article>`;
}

function renderOverview() {
  const cards = [];
  const ransomware = overviewState.ransomware;
  if (ransomware?.error) {
    cards.push(overviewPlaceholder('Ransomware', ransomware.error));
  } else if (ransomware?.items?.length) {
    const top = ransomware.items[0];
    cards.push(overviewCard({
      domain: 'Ransomware', status: 'RansomLook · 30 days', route: 'ransomware-watchlist',
      title: displayGroupName(top.name),
      summary: `${number(top.claim_count)} unique public victim claims were observed for the leading group during the rolling ${number(ransomware.window_days)}-day window. Claims are source-reported and not independently confirmed.`,
      stats: [
        { value: number(top.claim_count), label: '30-day claims' },
        { value: number(top.recent_7d_count), label: 'Latest seven days' },
        { value: `${number(top.share_percentage)}%`, label: 'Share of all claims' },
      ],
      chartTitle: 'Top five groups by claims',
      chart: barRows(ransomware.items.slice(0, 5), (item) => item.claim_count, (item) => displayGroupName(item.name)),
    }));
  } else cards.push(overviewPlaceholder('Ransomware'));

  const cwe = overviewState.cwe;
  if (cwe?.error) {
    cards.push(overviewPlaceholder('CWE', cwe.error));
  } else if (cwe?.items?.length) {
    const top = cwe.items[0];
    const name = top.Name && top.Name !== `CWE-${top.ID}` ? ` · ${top.Name}` : '';
    cards.push(overviewCard({
      domain: 'CWE', status: 'Weakness patterns', route: 'cwe-watchlist',
      title: `CWE-${top.ID}${name}`,
      summary: cleanText(top.Description || 'The weakness patterns most connected to active exploitation and near-term exploit probability.').slice(0, 220),
      stats: [
        { value: number(top.threat_score), label: 'Threat score' },
        { value: number(top.kev_count), label: 'Known exploited CVEs' },
        { value: `${number(top.epss_percentile)}%`, label: 'EPSS percentile' },
      ],
      chartTitle: 'Top five weakness scores',
      chart: barRows(cwe.items.slice(0, 5), (item) => item.threat_score, (item) => `CWE-${item.ID}`, 100),
    }));
  } else cards.push(overviewPlaceholder('CWE'));

  const cve = overviewState.cve;
  if (cve?.error) {
    cards.push(overviewPlaceholder('CVE', cve.error));
  } else if (cve?.items?.length) {
    const top = cve.items[0];
    cards.push(overviewCard({
      domain: 'CVE', status: 'Active vulnerabilities', route: 'cve-watchlist',
      title: top.id,
      summary: cleanText(top.name || top.description || top.short_description || 'Recently exploited vulnerabilities ranked using exploitation, ransomware, probability, recency, and severity signals.').slice(0, 220),
      stats: [
        { value: number(top.threat_score), label: 'Threat score' },
        { value: `${number(top.epss_probability)}%`, label: 'EPSS probability' },
        { value: top.cvss_score ? number(top.cvss_score) : 'N/A', label: 'CVSS base score' },
      ],
      chartTitle: 'Top five exploit probabilities',
      chart: barRows(cve.items.slice(0, 5), (item) => item.epss_probability, (item) => item.id, 100),
    }));
  } else cards.push(overviewPlaceholder('CVE'));

  const dshield = overviewState.dshield;
  if (dshield?.error) {
    cards.push(overviewPlaceholder('Honeypots', dshield.error));
  } else if (dshield?.generated_at) {
    const topAttacker = dshield.top_attackers?.[0];
    const topPort = dshield.top_ports?.[0];
    cards.push(overviewCard({
      domain: 'Honeypots', status: 'DShield community feed', route: 'dshield-activity',
      title: `${number(dshield.indicator_total)} observed indicators`,
      summary: `Current attacker, service, SSH, and web-scanning signals reported by the global DShield sensor community. Last refreshed ${formatDateTime(dshield.generated_at)}.`,
      stats: [
        { value: number(topAttacker?.reports), label: 'Top source reports' },
        { value: topPort ? `${topPort.port} · ${portNames[topPort.port] || 'Other'}` : 'N/A', label: 'Top targeted port' },
        { value: number(dshield.indicator_counts?.ssh), label: 'SSH indicators' },
      ],
      chartTitle: 'Top five targeted ports',
      chart: dshield.top_ports?.length ? barRows(dshield.top_ports.slice(0, 5), (item) => item.records, (item) => `${item.port} · ${portNames[item.port] || 'Other'}`) : '<p class="chart-empty">Port data is unavailable.</p>',
    }));
  } else cards.push(overviewPlaceholder('Honeypots'));

  document.querySelector('#overview-cards').innerHTML = cards.join('');
}

document.querySelector('#overview-cards').addEventListener('click', (event) => {
  const link = event.target.closest('[data-route]');
  if (!link) return;
  event.preventDefault();
  showView(link.dataset.route);
});
document.querySelector('#overview-cards').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const card = event.target.closest('.overview-card[data-route]');
  if (!card) return;
  event.preventDefault();
  showView(card.dataset.route);
});

const lineColors = ['#ff5c35', '#1f8a70', '#7c5cff', '#d49b00', '#3273dc'];

function formatMonth(month) {
  const [year, monthNumber] = month.split('-').map(Number);
  return new Intl.DateTimeFormat('en-US', { month: 'short', year: '2-digit', timeZone: 'UTC' })
    .format(new Date(Date.UTC(year, monthNumber - 1, 1)));
}

function formatDay(value) {
  const [year, month, day] = value.split('-').map(Number);
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
    .format(new Date(Date.UTC(year, month - 1, day)));
}

function lineChart(series, ariaLabel, yAxisLabel = 'Cumulative KEV count', xAxisLabel = 'Catalog addition month', formatBucket = formatMonth) {
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
  const xLabels = labelIndexes.map((index) => `<text class="line-axis-label" x="${x(index)}" y="${height - 32}" text-anchor="middle">${formatBucket(points[index].month)}</text>`).join('');
  const plotMiddleY = (plot.top + height - plot.bottom) / 2;
  const axisTitles = `<text class="line-axis-title" x="${(plot.left + width - plot.right) / 2}" y="${height - 6}" text-anchor="middle">${escapeHtml(xAxisLabel)}</text><text class="line-axis-title" x="14" y="${plotMiddleY}" text-anchor="middle" transform="rotate(-90 14 ${plotMiddleY})">${escapeHtml(yAxisLabel)}</text>`;
  const paths = validSeries.map((item, seriesIndex) => {
    const color = lineColors[seriesIndex % lineColors.length];
    const path = item.points.map((point, index) => `${index ? 'L' : 'M'} ${x(index).toFixed(1)} ${y(Number(point.count) || 0).toFixed(1)}`).join(' ');
    const markers = item.points.map((point, index) => `<circle cx="${x(index)}" cy="${y(Number(point.count) || 0)}" r="3" fill="${color}"><title>${escapeHtml(item.label)} · ${formatBucket(point.month)}: ${Number(point.count).toLocaleString()}</title></circle>`).join('');
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

const portNames = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 6379: 'Redis', 8080: 'HTTP alt' };

function renderDshieldFeed(data) {
  const attackers = (data.top_attackers || []).slice(0, 10);
  const ports = (data.top_ports || []).slice(0, 10);
  const usernames = (data.usernames || []).slice(0, 10);
  const indicators = (data.indicators || []).slice(0, 60);
  const attackerRows = attackers.map((item) => `<tr><td>#${escapeHtml(item.rank)}</td><td>${escapeHtml(item.ip)}</td><td>${number(item.reports)}</td><td>${number(item.targets)}</td></tr>`).join('');
  const portRows = ports.map((item) => `<tr><td>${escapeHtml(item.port)}</td><td>${escapeHtml(portNames[item.port] || 'Other')}</td><td>${number(item.records)}</td><td>${number(item.sources)}</td></tr>`).join('');
  const usernameRows = usernames.map((item) => `<tr><td>${escapeHtml(item.username)}</td><td>${number(item.count)}</td><td>${formatDate(item.last_seen)}</td></tr>`).join('');
  const indicatorBadges = indicators.map((item) => `<span class="data-badge ${item.category === 'ssh' ? 'kev-badge' : ''}">${escapeHtml(item.ip)} · ${escapeHtml(item.category)}</span>`).join('');
  const empty = '<p class="chart-empty">This portion of the feed is temporarily unavailable.</p>';

  document.querySelector('#dshield-feed').innerHTML = `
    <article class="feed-panel"><p class="eyebrow">Network reports</p><h3>Top attacking IPs</h3>${attackerRows ? `<div class="feed-table-wrap"><table class="feed-table"><thead><tr><th>Rank</th><th>Source</th><th>Reports</th><th>Targets</th></tr></thead><tbody>${attackerRows}</tbody></table></div>` : empty}</article>
    <article class="feed-panel"><p class="eyebrow">Exposed services</p><h3>Most-targeted ports</h3>${portRows ? `<div class="feed-table-wrap"><table class="feed-table"><thead><tr><th>Port</th><th>Service</th><th>Records</th><th>Sources</th></tr></thead><tbody>${portRows}</tbody></table></div>` : empty}</article>
    <article class="feed-panel"><p class="eyebrow">Cowrie · Last 30 days</p><h3>Attempted SSH usernames</h3>${usernameRows ? `<div class="feed-table-wrap"><table class="feed-table"><thead><tr><th>Username</th><th>Attempts</th><th>Last seen</th></tr></thead><tbody>${usernameRows}</tbody></table></div>` : empty}</article>
    <article class="feed-panel"><p class="eyebrow">Attack distribution</p><h3>Top-port activity</h3>${ports.length ? barRows(ports.slice(0, 8), (item) => item.records, (item) => `${item.port} · ${portNames[item.port] || 'Other'}`) : empty}</article>
    <article class="feed-panel wide"><p class="eyebrow">Honeypot-derived intelligence</p><h3>Current SSH and web scanner indicators</h3><p class="chart-note">A compact sample from the DShield intelligence feed. Treat IP indicators as investigative leads rather than an automatic blocklist.</p>${indicatorBadges ? `<div class="indicator-cloud">${indicatorBadges}</div>` : empty}</article>`;
}

function renderDshieldCharts(data) {
  const attackers = (data.top_attackers || []).slice(0, 10);
  const broadestAttackers = [...(data.top_attackers || [])].sort((a, b) => Number(b.targets || 0) - Number(a.targets || 0)).slice(0, 10);
  const ports = (data.top_ports || []).slice(0, 10);
  const diversePorts = [...(data.top_ports || [])].sort((a, b) => Number(b.sources || 0) - Number(a.sources || 0)).slice(0, 10);
  const usernames = (data.usernames || []).slice(0, 10);
  const indicatorMix = [
    { label: 'SSH / Telnet attackers', count: data.indicator_counts?.ssh || 0 },
    { label: 'Web scanners', count: data.indicator_counts?.web || 0 },
  ];
  const empty = '<p class="chart-empty">This chart is temporarily unavailable.</p>';
  document.querySelector('#dshield-chart-grid').innerHTML = `
    <article class="chart-card chart-wide"><p class="eyebrow">Reported traffic</p><h3>Top attacker report volume</h3><p class="chart-note">The number of network reports associated with each of DShield's current top source addresses.</p>${attackers.length ? barRows(attackers, (item) => item.reports, (item) => item.ip) : empty}</article>
    <article class="chart-card"><p class="eyebrow">Scanning breadth</p><h3>Targets reached by attacker</h3><p class="chart-note">Distinct reporting targets associated with each source. Broad scanners may rank differently from high-volume sources.</p>${broadestAttackers.length ? barRows(broadestAttackers, (item) => item.targets, (item) => item.ip) : empty}</article>
    <article class="chart-card"><p class="eyebrow">Indicator composition</p><h3>SSH versus web scanners</h3><p class="chart-note">Honeypot-derived addresses currently labeled by DShield's public intelligence feed.</p>${barRows(indicatorMix, (item) => item.count, (item) => item.label)}</article>
    <article class="chart-card chart-wide"><p class="eyebrow">Service targeting</p><h3>Most-targeted port activity</h3><p class="chart-note">Reported connection volume for the leading destination ports in the current snapshot.</p>${ports.length ? barRows(ports, (item) => item.records, (item) => `${item.port} · ${portNames[item.port] || 'Other'}`) : empty}</article>
    <article class="chart-card"><p class="eyebrow">Source diversity</p><h3>Unique sources by port</h3><p class="chart-note">The number of distinct source addresses observed targeting each service.</p>${diversePorts.length ? barRows(diversePorts, (item) => item.sources, (item) => `${item.port} · ${portNames[item.port] || 'Other'}`) : empty}</article>
    <article class="chart-card"><p class="eyebrow">Cowrie · Last 30 days</p><h3>Attempted SSH usernames</h3><p class="chart-note">The most frequently attempted display-safe usernames collected by DShield Cowrie sensors.</p>${usernames.length ? barRows(usernames, (item) => item.count, (item) => item.username) : empty}</article>`;
}

function renderRansomwareCharts(data) {
  const items = data.items || [];
  const dailySeries = [{
    label: 'All observed claims',
    points: (data.daily_activity || []).map((item) => ({ month: item.date, count: item.count })),
  }];
  const empty = '<p class="chart-empty">This chart is temporarily unavailable.</p>';
  document.querySelector('#ransomware-chart-grid').innerHTML = `
    <article class="chart-card chart-wide"><p class="eyebrow">Discovery timeline · 30 days</p><h3>Daily public victim claims</h3><p class="chart-note">Unique claims across all observed groups, plotted by the date RansomLook first discovered each post.</p>${dailySeries[0].points.length ? lineChart(dailySeries, 'Daily public ransomware victim claims over the last 30 days', 'Observed claims', 'Discovery date', formatDay) : empty}</article>
    <article class="chart-card chart-wide"><p class="eyebrow">Rolling activity</p><h3>Thirty-day claim volume</h3><p class="chart-note">Unique public victim titles attributed to each group during the current rolling window.</p>${items.length ? barRows(items, (item) => item.claim_count, (item) => displayGroupName(item.name)) : empty}</article>
    <article class="chart-card"><p class="eyebrow">Current momentum</p><h3>Claims in the latest seven days</h3><p class="chart-note">Recent observations highlight groups whose current activity may differ from their full-window rank.</p>${items.length ? barRows(items, (item) => item.recent_7d_count, (item) => displayGroupName(item.name)) : empty}</article>
    <article class="chart-card"><p class="eyebrow">Activity concentration</p><h3>Share of all observed claims</h3><p class="chart-note">Each leading group's percentage of unique claims across the complete 30-day dataset.</p>${items.length ? barRows(items, (item) => item.share_percentage, (item) => displayGroupName(item.name), 100) : empty}</article>`;
}

async function loadDshieldDashboard() {
  document.querySelector('#dshield-feed').innerHTML = '<p class="loading">Loading DShield telemetry…</p>';
  try {
    const data = await getLocal('/api/dshield');
    if (data.error || !data.generated_at) throw new Error(data.error || 'No DShield records were returned.');
    overviewState.dshield = data;
    document.querySelector('#dshield-indicator-total').textContent = number(data.indicator_total);
    document.querySelector('#dshield-ssh-total').textContent = number(data.indicator_counts?.ssh);
    document.querySelector('#dshield-web-total').textContent = number(data.indicator_counts?.web);
    document.querySelector('#dshield-updated').textContent = formatDateTime(data.generated_at);
    document.querySelector('#dshield-notices').innerHTML = (data.errors || []).map((message) => `<p class="feed-warning">${escapeHtml(message)}</p>`).join('');
    renderDshieldFeed(data);
    renderDshieldCharts(data);
    renderOverview();
  } catch (error) {
    overviewState.dshield = { error: error.message };
    document.querySelector('#dshield-feed').innerHTML = `<p class="loading error">Unable to load DShield telemetry. ${escapeHtml(error.message)}</p>`;
    document.querySelector('#dshield-chart-grid').innerHTML = `<p class="loading error">Unable to load DShield charts. ${escapeHtml(error.message)}</p>`;
    renderOverview();
  }
}

async function loadRansomwareDashboard() {
  document.querySelector('#ransomware-grid').innerHTML = '<p class="loading">Loading ransomware activity…</p>';
  try {
    const data = await getLocal('/api/ransomware');
    if (data.error || !data.items?.length) throw new Error(data.error || 'No ransomware group activity was returned.');
    overviewState.ransomware = data;
    document.querySelector('#ransomware-total-claims').textContent = number(data.total_claims);
    document.querySelector('#ransomware-active-groups').textContent = number(data.active_groups);
    document.querySelector('#ransomware-leading-share').textContent = `${number(data.items[0]?.share_percentage)}%`;
    document.querySelector('#ransomware-updated').textContent = formatDateTime(data.generated_at);
    document.querySelector('#ransomware-notices').innerHTML = data.warning ? `<p class="feed-warning">${escapeHtml(data.warning)}</p>` : '';
    renderRansomwareCards(data.items);
    renderRansomwareCharts(data);
    renderOverview();
  } catch (error) {
    overviewState.ransomware = { error: error.message };
    document.querySelector('#ransomware-grid').innerHTML = `<p class="loading error">Unable to load ransomware activity. ${escapeHtml(error.message)}</p>`;
    document.querySelector('#ransomware-chart-grid').innerHTML = `<p class="loading error">Unable to load ransomware charts. ${escapeHtml(error.message)}</p>`;
    renderOverview();
  }
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
    overviewState.cwe = { ...watchlist, items: cweRecords };
    document.querySelector('#download-report').disabled = false;
    renderCweCards(cweRecords);
    renderCweCharts(cweRecords, watchlist.exploitation_timeline);
    renderOverview();

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
    overviewState.cwe = { ...watchlist, items: cweRecords };
    renderCweCards(cweRecords);
    renderOverview();
  } catch (error) {
    cweRecords = [];
    overviewState.cwe = { error: error.message };
    document.querySelector('#download-report').disabled = true;
    document.querySelector('#weakness-grid').innerHTML = `<p class="loading error">Unable to load live CWE data. ${escapeHtml(error.message)}</p>`;
    document.querySelector('#cwe-chart-grid').innerHTML = '<p class="loading error">CWE charts are unavailable.</p>';
    renderOverview();
  }
}

async function loadCveDashboard() {
  document.querySelector('#cve-grid').innerHTML = '<p class="loading">Loading live CVE records…</p>';
  try {
    const watchlist = await getLocal('/api/cve-watchlist');
    if (!watchlist.items?.length) throw new Error(watchlist.error || 'No threat-ranked CVEs were returned.');
    cveRecords = watchlist.items;
    overviewState.cve = { ...watchlist, items: cveRecords };
    document.querySelector('#cve-window').textContent = `${watchlist.window_days}d`;
    document.querySelector('#cve-candidate-count').textContent = Number(watchlist.candidate_count || 0).toLocaleString();
    document.querySelector('#cve-ransomware-count').textContent = cveRecords.filter((item) => item.ransomware).length;
    document.querySelector('#cve-catalog-date').textContent = formatDate(watchlist.catalog_date);
    renderCveCards(cveRecords);
    renderCveCharts(cveRecords, watchlist.exploitation_timeline);
    renderOverview();
  } catch (error) {
    cveRecords = [];
    overviewState.cve = { error: error.message };
    document.querySelector('#cve-grid').innerHTML = `<p class="loading error">Unable to load live CVE data. ${escapeHtml(error.message)}</p>`;
    document.querySelector('#cve-chart-grid').innerHTML = '<p class="loading error">CVE charts are unavailable.</p>';
    renderOverview();
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

document.querySelector('#dshield-lookup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const address = document.querySelector('#dshield-ip').value.trim();
  const result = document.querySelector('#dshield-record-result');
  result.hidden = false;
  result.innerHTML = '<p class="loading">Querying DShield…</p>';
  try {
    const item = await getLocal(`/api/dshield/ip/${encodeURIComponent(address)}`);
    if (item.error || !item.ip) throw new Error(item.error || 'No DShield record was returned.');
    renderRecord(result, 'DShield IP reputation', item.ip, item.comment || 'Community observations reported to the DShield distributed sensor network.', [
      `${number(item.reports)} reports`, `${number(item.targets)} targets`,
      item.first_seen ? `First seen ${formatDate(item.first_seen)}` : 'First seen unavailable',
      item.last_seen ? `Last seen ${formatDate(item.last_seen)}` : 'Last seen unavailable',
      item.country || 'Country unavailable', item.asn ? `AS${item.asn}` : 'ASN unavailable',
      item.as_name || '', item.network || '',
    ].filter(Boolean), [`https://isc.sans.edu/ipinfo/${encodeURIComponent(item.ip)}`]);
  } catch (error) {
    result.innerHTML = `<p class="error">${escapeHtml(error.message || 'Unable to look up this IP address.')}</p>`;
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
document.querySelector('.dshield-refresh').addEventListener('click', (event) => {
  const button = event.currentTarget;
  button.textContent = 'Refreshing…';
  loadDshieldDashboard().finally(() => { button.textContent = 'Refresh data ↻'; });
});
document.querySelector('.ransomware-refresh').addEventListener('click', (event) => {
  const button = event.currentTarget;
  button.textContent = 'Refreshing…';
  loadRansomwareDashboard().finally(() => { button.textContent = 'Refresh data ↻'; });
});
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
  pdf.text('THREAT WATCH — CWE TOP 10', 50, y);
  y += 35;
  cweRecords.forEach((item, index) => {
    const lines = pdf.splitTextToSize(cleanText(item.Description || 'No description returned.'), 495);
    const itemHeight = 62 + lines.length * 11;
    if (y + itemHeight > 790) {
      pdf.addPage();
      y = 55;
    }
    pdf.setFontSize(13);
    pdf.text(`${index + 1}. CWE-${item.ID}: ${item.Name}`, 50, y);
    y += 18;
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.text(`Score ${item.threat_score} | KEVs ${item.kev_count} | Ransomware ${item.ransomware_count} | EPSS ${item.epss_percentile}%`, 50, y);
    y += 20;
    pdf.text(lines, 50, y);
    y += lines.length * 11 + 24;
    pdf.setFont('helvetica', 'bold');
  });
  pdf.save(`threat-watch-cwe-top-10-${new Date().toISOString().slice(0, 10)}.pdf`);
});

Promise.all([loadCweDashboard(), loadCveDashboard(), loadDshieldDashboard(), loadRansomwareDashboard()]);
