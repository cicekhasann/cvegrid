(function () {
  'use strict';

  // State Management
  const state = {
    category: 'ALL',
    severity: 'ALL',
    ransomwareOnly: false,
    search: '',
    sort: 'date_desc',
    dateAdded: '',
    vector: '',
    epssTier: '',
    ecosystem: '',
    techTag: '',
    activeEcoTab: 'vendors',
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 1,
    items: [],
    selectedIndex: 0,
    isSyncing: false,
  };

  // Top HUD Elements
  const hudTotal = document.getElementById('hudTotal');
  const hudCritical = document.getElementById('hudCritical');
  const hudRansomware = document.getElementById('hudRansomware');
  const hudAvgEPSS = document.getElementById('hudAvgEPSS');
  const hudLastSync = document.getElementById('hudLastSync');
  const btnSync = document.getElementById('btnSync');
  const btnSyncText = document.getElementById('btnSyncText');

  // Heatmap Elements
  const heatmapCells = document.getElementById('heatmapCells');
  const heatmapActiveFilter = document.getElementById('heatmapActiveFilter');
  const heatmapFilterDate = document.getElementById('heatmapFilterDate');
  const btnClearDateFilter = document.getElementById('btnClearDateFilter');
  const heatmapTooltip = document.getElementById('heatmapTooltip');

  // Matrix Elements
  const matrixTableBody = document.getElementById('matrixTableBody');
  const matrixCountDisplay = document.getElementById('matrixCountDisplay');
  const filterChips = document.getElementById('filterChips');
  const chipRansomware = document.getElementById('chipRansomware');
  const searchInput = document.getElementById('searchInput');
  const severitySelect = document.getElementById('severitySelect');
  const sortSelect = document.getElementById('sortSelect');
  const btnPrevPage = document.getElementById('btnPrevPage');
  const btnNextPage = document.getElementById('btnNextPage');
  const pageIndicator = document.getElementById('pageIndicator');
  const paginationSummary = document.getElementById('paginationSummary');

  // Dossier Elements
  const dossierCveId = document.getElementById('dossierCveId');
  const dossierTargetSub = document.getElementById('dossierTargetSub');
  const btnCopyCve = document.getElementById('btnCopyCve');
  const dossierRansomwareBanner = document.getElementById('dossierRansomwareBanner');
  const dossierTechPills = document.getElementById('dossierTechPills');

  // Dynamic Kill Chain Elements
  const dossierKillchainCard = document.getElementById('dossierKillchainCard');
  const dossierKillchainFlow = document.getElementById('dossierKillchainFlow');
  const killchainStatusTag = document.getElementById('killchainStatusTag');

  // Tier Navigation
  const tabTierHuman = document.getElementById('tabTierHuman');
  const tabTierPro = document.getElementById('tabTierPro');
  const panelTierHuman = document.getElementById('panelTierHuman');
  const panelTierPro = document.getElementById('panelTierPro');

  // 3 Instant Badges
  const badgeUrgency = document.getElementById('badgeUrgency');
  const badgeExploit = document.getElementById('badgeExploit');
  const badgeAction = document.getElementById('badgeAction');

  // Tier 1: Human-First Elements
  const dossierTldr = document.getElementById('dossierTldr');
  const dossierDueTag = document.getElementById('dossierDueTag');
  const dossierChecklist = document.getElementById('dossierChecklist');
  const dossierCuratedCards = document.getElementById('dossierCuratedCards');

  // Tier 2: Pro Inspector Elements
  const dossierEpssVal = document.getElementById('dossierEpssVal');
  const dossierEpssBar = document.getElementById('dossierEpssBar');
  const dossierEpssRiskText = document.getElementById('dossierEpssRiskText');
  const dossierEpssPercentile = document.getElementById('dossierEpssPercentile');
  const dossierVendor = document.getElementById('dossierVendor');
  const dossierProduct = document.getElementById('dossierProduct');
  const dossierCwe = document.getElementById('dossierCwe');
  const dossierCweDesc = document.getElementById('dossierCweDesc');
  const dossierCvss = document.getElementById('dossierCvss');
  const dossierVectorStr = document.getElementById('dossierVectorStr');
  const dossierVector = document.getElementById('dossierVector');
  const dossierDate = document.getElementById('dossierDate');
  const dossierDesc = document.getElementById('dossierDesc');
  const btnNist = document.getElementById('btnNist');

  // Right Column Metrics Elements
  const epssTierGroup = document.getElementById('epssTierGroup');
  const metricEpssCrit = document.getElementById('metricEpssCrit');
  const metricEpssHigh = document.getElementById('metricEpssHigh');
  const metricEpssLow = document.getElementById('metricEpssLow');
  const ecoTabBar = document.getElementById('ecoTabBar');
  const activeEcoSub = document.getElementById('activeEcoSub');
  const metricsVendorsList = document.getElementById('metricsVendorsList');
  const vectorSegmentedBar = document.getElementById('vectorSegmentedBar');
  const metricsVectorList = document.getElementById('metricsVectorList');

  // Cache for stats telemetry
  let latestStats = null;

  // Toast
  const ctiToast = document.getElementById('ctiToast');

  function showToast(msg) {
    ctiToast.textContent = msg;
    ctiToast.classList.add('show');
    setTimeout(() => {
      ctiToast.classList.remove('show');
    }, 2500);
  }

  function formatNumber(num) {
    return new Intl.NumberFormat().format(num || 0);
  }

  // API Invocations
  async function fetchStats() {
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) return;
      const data = await res.json();
      latestStats = data;

      hudTotal.textContent = formatNumber(data.total_records);
      hudCritical.textContent = formatNumber(data.critical_count);
      hudRansomware.textContent = formatNumber(data.ransomware_count);
      hudAvgEPSS.textContent = (data.avg_epss * 100).toFixed(1) + '%';
      hudLastSync.textContent = data.last_sync || 'NEVER';

      // 1. EPSS Risk Tiers Filter Buttons
      metricEpssCrit.textContent = formatNumber(data.epss_critical);
      metricEpssHigh.textContent = formatNumber(data.epss_high);
      metricEpssLow.textContent = formatNumber(data.epss_low);

      if (epssTierGroup) {
        epssTierGroup.querySelectorAll('.epss-tier-btn').forEach(btn => {
          btn.classList.toggle('active', btn.dataset.tier === state.epssTier);
        });
      }

      // 2. Render Ecosystem Telemetry Slices (Vendors, Languages, Packages, Kernels)
      renderEcosystemTelemetry();

      // 3. Attack Vector Breakdown: Multi-Segmented Ratio Bar
      const vectorCounts = data.vector_counts || [];
      let netCount = 0, locCount = 0, othCount = 0;
      vectorCounts.forEach(vc => {
        const vUpper = (vc.vector || '').toUpperCase();
        if (vUpper.includes('NETWORK') || vUpper.includes('REMOTE')) {
          netCount += vc.count;
        } else if (vUpper.includes('LOCAL') || vUpper.includes('PRIVESC')) {
          locCount += vc.count;
        } else {
          othCount += vc.count;
        }
      });
      const vecTotal = Math.max(netCount + locCount + othCount, 1);
      const netPct = Math.round((netCount / vecTotal) * 100);
      const locPct = Math.round((locCount / vecTotal) * 100);
      const othPct = Math.max(0, 100 - netPct - locPct);

      if (vectorSegmentedBar) {
        vectorSegmentedBar.innerHTML = `
          <div class="segment-fill seg-network" style="width: ${netPct}%;" title="Network / Remote: ${formatNumber(netCount)} (${netPct}%)" data-vec="NETWORK"></div>
          <div class="segment-fill seg-local" style="width: ${locPct}%;" title="Local / Privesc: ${formatNumber(locCount)} (${locPct}%)" data-vec="LOCAL"></div>
          <div class="segment-fill seg-other" style="width: ${othPct}%;" title="Physical / Other: ${formatNumber(othCount)} (${othPct}%)" data-vec="PHYSICAL"></div>
        `;
      }

      if (metricsVectorList) {
        metricsVectorList.innerHTML = `
          <div class="vector-pill ${state.vector === 'NETWORK' ? 'active' : ''}" data-vec="NETWORK">
            <span class="legend-dot dot-network"></span>
            <span class="legend-title">NETWORK</span>
            <span class="legend-count">${netPct}%</span>
          </div>
          <div class="vector-pill ${state.vector === 'LOCAL' ? 'active' : ''}" data-vec="LOCAL">
            <span class="legend-dot dot-local"></span>
            <span class="legend-title">LOCAL</span>
            <span class="legend-count">${locPct}%</span>
          </div>
          <div class="vector-pill ${state.vector === 'PHYSICAL' ? 'active' : ''}" data-vec="PHYSICAL">
            <span class="legend-dot dot-other"></span>
            <span class="legend-title">OTHER</span>
            <span class="legend-count">${othPct}%</span>
          </div>
        `;
      }

      // 4. Threat Activity Mini Heatmap Strip (30 Days)
      renderHeatmap(data.daily_activities || []);
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  }

  function renderEcosystemTelemetry() {
    if (!metricsVendorsList || !latestStats) return;
    metricsVendorsList.innerHTML = '';

    const tab = state.activeEcoTab || 'vendors';
    let items = [];
    let isVendorTab = false;

    if (tab === 'vendors') {
      isVendorTab = true;
      items = (latestStats.top_vendors || []).map(v => ({ name: v.vendor, count: v.count }));
      if (activeEcoSub) activeEcoSub.textContent = 'TOP VENDORS';
    } else if (tab === 'languages') {
      items = latestStats.top_languages || [];
      if (activeEcoSub) activeEcoSub.textContent = 'RUNTIMES & LANGS';
    } else if (tab === 'packages') {
      items = latestStats.top_packages || [];
      if (activeEcoSub) activeEcoSub.textContent = 'CORE PACKAGES';
    } else if (tab === 'kernels') {
      items = latestStats.top_kernels || [];
      if (activeEcoSub) activeEcoSub.textContent = 'KERNELS & OS';
    }

    if (items.length === 0) {
      metricsVendorsList.innerHTML = `
        <div style="text-align: center; padding: 1.5rem 0.5rem; color: var(--text-dim); font-size: 0.72rem;">
          NO TELEMETRY RECORDED FOR THIS SLICE
        </div>
      `;
      return;
    }

    const maxCount = items.reduce((max, it) => Math.max(max, it.count), 1);

    items.forEach(it => {
      const row = document.createElement('div');
      let isActive = false;
      if (isVendorTab) {
        isActive = state.search.toLowerCase() === it.name.toLowerCase();
      } else {
        isActive = state.techTag.toLowerCase() === it.name.toLowerCase();
      }

      row.className = `vendor-capacity-row ${isActive ? 'active' : ''}`;
      const pct = Math.round((it.count / maxCount) * 100);
      row.innerHTML = `
        <div class="vendor-bar-bg" style="width: ${pct}%"></div>
        <div class="vendor-label">
          <span class="vendor-name">${escapeHtml(it.name)}</span>
          <span class="vendor-count">${formatNumber(it.count)}</span>
        </div>
      `;

      row.addEventListener('click', () => {
        if (isVendorTab) {
          if (state.search.toLowerCase() === it.name.toLowerCase()) {
            state.search = '';
            searchInput.value = '';
          } else {
            state.search = it.name;
            searchInput.value = it.name;
          }
        } else {
          if (state.techTag.toLowerCase() === it.name.toLowerCase()) {
            state.techTag = '';
          } else {
            state.techTag = it.name;
          }
        }
        state.page = 1;
        fetchVulnerabilities();
        renderEcosystemTelemetry();
      });

      metricsVendorsList.appendChild(row);
    });
  }

  function renderHeatmap(activities) {
    if (!heatmapCells) return;
    heatmapCells.innerHTML = '';

    const actMap = new Map();
    activities.forEach(a => {
      actMap.set(a.date, a);
    });

    // Build 30 discrete date cells
    let dates = [];
    if (activities.length >= 30) {
      dates = activities.slice(-30).map(a => a.date);
    } else {
      let baseDate = new Date();
      if (activities.length > 0) {
        const latestStr = activities[activities.length - 1].date;
        const parsed = new Date(latestStr);
        if (!isNaN(parsed.getTime())) {
          baseDate = parsed;
        }
      }
      for (let i = 29; i >= 0; i--) {
        const d = new Date(baseDate);
        d.setDate(baseDate.getDate() - i);
        dates.push(d.toISOString().slice(0, 10));
      }
    }

    dates.forEach(dStr => {
      const item = actMap.get(dStr) || { date: dStr, total_count: 0, critical_count: 0 };
      const cell = document.createElement('div');
      cell.className = 'heatmap-cell';
      if (state.dateAdded === dStr) {
        cell.classList.add('active');
      }

      // Determine level
      if (item.total_count === 0) {
        cell.classList.add('lvl-0');
      } else if (item.critical_count > 0 || item.total_count >= 8) {
        cell.classList.add('lvl-crit');
      } else if (item.total_count >= 5) {
        cell.classList.add('lvl-3');
      } else if (item.total_count >= 3) {
        cell.classList.add('lvl-2');
      } else {
        cell.classList.add('lvl-1');
      }

      cell.dataset.date = dStr;
      cell.dataset.count = item.total_count;
      cell.dataset.crit = item.critical_count;

      // Tooltip events
      cell.addEventListener('mouseenter', (e) => {
        if (!heatmapTooltip) return;
        heatmapTooltip.textContent = `Date: ${dStr} | Count: ${item.total_count} (Critical: ${item.critical_count})`;
        heatmapTooltip.style.display = 'block';
        updateTooltipPos(e);
      });
      cell.addEventListener('mousemove', (e) => {
        updateTooltipPos(e);
      });
      cell.addEventListener('mouseleave', () => {
        if (heatmapTooltip) heatmapTooltip.style.display = 'none';
      });

      // Click to filter by publication date
      cell.addEventListener('click', () => {
        if (state.dateAdded === dStr) {
          state.dateAdded = '';
        } else {
          state.dateAdded = dStr;
        }
        state.page = 1;
        updateHeatmapFilterIndicator();
        fetchVulnerabilities();
        renderHeatmap(activities);
      });

      heatmapCells.appendChild(cell);
    });

    updateHeatmapFilterIndicator();
  }

  function updateTooltipPos(e) {
    if (!heatmapTooltip) return;
    const x = e.clientX + 10;
    const y = e.clientY - 30;
    heatmapTooltip.style.left = `${x}px`;
    heatmapTooltip.style.top = `${y}px`;
  }

  function updateHeatmapFilterIndicator() {
    if (!heatmapActiveFilter) return;
    if (state.dateAdded) {
      heatmapActiveFilter.style.display = 'flex';
      heatmapFilterDate.textContent = state.dateAdded;
    } else {
      heatmapActiveFilter.style.display = 'none';
    }
  }

  async function fetchVulnerabilities() {
    try {
      matrixTableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 2rem; color: var(--text-dim);">
            QUERYING THREAT INTELLIGENCE MATRIX...
          </td>
        </tr>
      `;

      const params = new URLSearchParams({
        category: state.category,
        severity: state.severity,
        ransomware_only: state.ransomwareOnly ? 'true' : 'false',
        search: state.search,
        sort: state.sort,
        page: state.page,
        limit: state.limit,
      });

      if (state.dateAdded) {
        params.set('date', state.dateAdded);
      }
      if (state.vector) {
        params.set('vector', state.vector);
      }
      if (state.epssTier) {
        params.set('epss_tier', state.epssTier);
      }
      if (state.ecosystem) {
        params.set('ecosystem', state.ecosystem);
      }
      if (state.techTag) {
        params.set('tech', state.techTag);
      }

      const res = await fetch(`/api/vulnerabilities?${params.toString()}`);
      if (!res.ok) throw new Error('API query failed');
      const data = await res.json();

      state.items = data.items || [];
      state.total = data.total || 0;
      state.totalPages = data.total_pages || 1;
      state.selectedIndex = 0;

      renderMatrixTable();
      updatePagination();

      if (state.items.length > 0) {
        displayDossier(state.items[0]);
      } else {
        clearDossier();
      }
    } catch (err) {
      matrixTableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 2rem; color: var(--crimson);">
            Database communication error: ${err.message}
          </td>
        </tr>
      `;
    }
  }

  function renderMatrixTable() {
    matrixCountDisplay.textContent = `${formatNumber(state.total)} RECORDS`;

    if (state.items.length === 0) {
      matrixTableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 2.5rem; color: var(--text-dim);">
            No records match the active telemetry filters.
          </td>
        </tr>
      `;
      return;
    }

    matrixTableBody.innerHTML = '';
    state.items.forEach((item, idx) => {
      const tr = document.createElement('tr');
      if (idx === state.selectedIndex) {
        tr.classList.add('active-row');
      }

      tr.addEventListener('click', () => {
        selectRow(idx);
      });

      // Severity badge
      let sevBadge = `<span class="c-badge c-badge-high">${item.score.toFixed(1)}</span>`;
      if (item.score >= 9.0) {
        sevBadge = `<span class="c-badge c-badge-crit">${item.score.toFixed(1)}</span>`;
      } else if (item.score < 4.0) {
        sevBadge = `<span class="c-badge c-badge-low">${item.score.toFixed(1)}</span>`;
      }

      // EPSS display with micro progress bar
      const epssPct = (item.epss_score * 100).toFixed(1) + '%';
      const epssVal = Math.min(100, Math.max(0, item.epss_score * 100));
      let epssColor = 'var(--text-main)';
      let epssLevelClass = 'low';
      let isCrit = false;
      if (item.epss_score >= 0.80) {
        epssColor = 'var(--crimson)';
        epssLevelClass = 'crit';
        isCrit = true;
      } else if (item.epss_score >= 0.50) {
        epssColor = 'var(--amber)';
        epssLevelClass = 'high';
      } else {
        epssColor = 'var(--emerald)';
        epssLevelClass = 'low';
      }

      // Ransomware badge
      const ransomBadge = item.ransomware_campaign === 1
        ? `<span class="c-badge c-badge-ransom">RANSOM</span>`
        : `<span style="color: var(--text-dark);">─</span>`;

      // Target layout: Product on top (bold white), Vendor directly beneath (muted)
      const prodName = escapeHtml(item.product || 'Unknown Product');
      const vendorName = escapeHtml(item.vendor || 'Unknown Vendor');

      tr.innerHTML = `
        <td class="date-cell">${escapeHtml(item.date_added)}</td>
        <td class="cve-cell">${escapeHtml(item.cve_id)}</td>
        <td class="target-cell">
          <div class="target-product" title="${prodName}">${prodName}</div>
          <div class="target-vendor">${vendorName}</div>
        </td>
        <td><span class="c-badge c-badge-cwe">${escapeHtml(item.cwe_id || 'N/A')}</span></td>
        <td>${sevBadge}</td>
        <td class="epss-cell">
          <div class="epss-micro-wrap">
            <span class="epss-micro-label" style="color: ${epssColor};">${epssPct}</span>
            <div class="epss-micro-track">
              <div class="epss-micro-fill ${epssLevelClass}" style="width: ${epssVal}%;"></div>
            </div>
            ${isCrit ? '<span class="epss-glow-dot" title="Critical EPSS Risk (>80%)"></span>' : ''}
          </div>
        </td>
        <td style="text-align: center;">${ransomBadge}</td>
      `;

      matrixTableBody.appendChild(tr);
    });
  }

  function selectRow(index) {
    if (index < 0 || index >= state.items.length) return;
    state.selectedIndex = index;

    // Highlight row
    const rows = matrixTableBody.querySelectorAll('tr');
    rows.forEach((r, i) => {
      if (i === index) {
        r.classList.add('active-row');
        r.scrollIntoView({ block: 'nearest' });
      } else {
        r.classList.remove('active-row');
      }
    });

    displayDossier(state.items[index]);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function convertUrlsToSmartPills(text) {
    if (!text) return '';
    const urlRegex = /(https?:\/\/[^\s|<>"']+)/g;
    return text.replace(urlRegex, (url) => {
      let cleanUrl = url;
      let trailingPunct = '';
      if (/[.,;)]$/.test(cleanUrl)) {
        trailingPunct = cleanUrl.slice(-1);
        cleanUrl = cleanUrl.slice(0, -1);
      }
      let label = '↗ Official Advisory';
      const uLower = cleanUrl.toLowerCase();
      if (uLower.includes('cisa.gov')) {
        label = '↗ CISA Guidance';
      } else if (uLower.includes('nvd.nist.gov')) {
        label = '↗ NIST Advisory';
      } else if (uLower.includes('github.com')) {
        label = '↗ GitHub Advisory';
      } else if (uLower.includes('microsoft.com') || uLower.includes('cisco.com') || uLower.includes('fortinet.com') || uLower.includes('ivanti.com') || uLower.includes('apple.com')) {
        label = '↗ Vendor Advisory';
      } else if (uLower.includes('patch') || uLower.includes('bulletin')) {
        label = '↗ Patch Details';
      }
      return `<a href="${escapeHtml(cleanUrl)}" target="_blank" rel="noopener noreferrer" class="smart-link-pill">${label}</a>${trailingPunct}`;
    });
  }

  function renderKillChain(item) {
    if (!dossierKillchainFlow) return;

    // Stage 1: Vector & Authentication Requirement
    const vecRaw = item.vector || 'NETWORK / REMOTE';
    let authReq = 'Unauthenticated Remote Access';
    const cvss = (item.cvss_vector || '').toUpperCase();
    if (cvss.includes('PR:N')) {
      authReq = 'Pre-Auth / Zero Credentials Required';
    } else if (cvss.includes('PR:L')) {
      authReq = 'Low Privileged Account Required';
    } else if (cvss.includes('PR:H')) {
      authReq = 'High Privileged / Admin Access Required';
    } else if (vecRaw.toUpperCase().includes('LOCAL')) {
      authReq = 'Local Interactive Shell Access';
    }

    // Stage 2: MITRE CWE Flaw Mechanism
    const cweId = item.cwe_id || 'CWE Flaw';
    let flawDesc = item.cwe_description || 'Common software weakness categorized by MITRE.';
    if (flawDesc.length > 70) {
      flawDesc = flawDesc.slice(0, 68) + '...';
    }

    // Stage 3: System Impact & Blast Radius
    let impactTitle = 'System Exposure & Tampering';
    let impactDesc = 'Integrity, Confidentiality & Service Disruption';
    if (item.score >= 9.0) {
      impactTitle = 'Arbitrary Code Execution (RCE)';
      impactDesc = 'Host Takeover & Full System Compromise';
    } else if (vecRaw.toUpperCase().includes('LOCAL') || vecRaw.toUpperCase().includes('PRIVESC')) {
      impactTitle = 'Root / Admin PrivEsc';
      impactDesc = 'Local Kernel or System Security Bypass';
    }

    let ransomAlert = '';
    if (item.ransomware_campaign === 1) {
      ransomAlert = `<div class="killchain-ransom-tag">🚨 RANSOMWARE WEAPONIZED</div>`;
      if (killchainStatusTag) {
        killchainStatusTag.textContent = '🚨 RANSOMWARE ACTIVE';
        killchainStatusTag.style.borderColor = 'var(--crimson)';
        killchainStatusTag.style.color = 'var(--crimson)';
      }
    } else {
      if (killchainStatusTag) {
        killchainStatusTag.textContent = 'WEAPONIZED PATHWAY';
        killchainStatusTag.style.borderColor = 'rgba(56, 189, 248, 0.3)';
        killchainStatusTag.style.color = 'var(--sky-bright)';
      }
    }

    let stackInfo = '';
    if (item.tech_tags && item.tech_tags.length > 0) {
      stackInfo = `<div style="margin-top: 4px; font-size: 0.62rem; color: var(--sky-bright);">Target: ${escapeHtml(item.tech_tags.join(', '))}</div>`;
    }

    dossierKillchainFlow.innerHTML = `
      <div class="killchain-stage">
        <span class="stage-tag">STAGE 01 // INITIAL ACCESS</span>
        <div class="stage-title">${escapeHtml(vecRaw)}</div>
        <div class="stage-desc">${escapeHtml(authReq)}</div>
        ${stackInfo}
      </div>
      <div class="killchain-arrow">──►</div>
      <div class="killchain-stage">
        <span class="stage-tag">STAGE 02 // EXPLOIT MECHANISM</span>
        <div class="stage-title mono-font">${escapeHtml(cweId)}</div>
        <div class="stage-desc">${escapeHtml(flawDesc)}</div>
      </div>
      <div class="killchain-arrow">──►</div>
      <div class="killchain-stage">
        <span class="stage-tag">STAGE 03 // BLAST RADIUS</span>
        <div class="stage-title">${escapeHtml(impactTitle)}</div>
        <div class="stage-desc">${escapeHtml(impactDesc)}</div>
        ${ransomAlert}
      </div>
    `;
  }

  function displayDossier(item) {
    dossierCveId.textContent = item.cve_id;
    dossierTargetSub.textContent = `${item.product || 'Unknown Product'} (${item.vendor || 'Unknown Vendor'})`;

    // 1. 3 Instant Badges
    const urg = item.urgency || 'SCHEDULE MAINTENANCE';
    badgeUrgency.textContent = `URGENCY: ${urg}`;
    if (urg.includes('IMMEDIATE')) {
      badgeUrgency.className = 'instant-badge badge-urgency';
    } else if (urg.includes('SCHEDULE')) {
      badgeUrgency.className = 'instant-badge badge-urgency yellow';
    } else {
      badgeUrgency.className = 'instant-badge badge-urgency blue';
    }

    const expStatus = item.exploit_status || 'ACTIVE IN WILD';
    badgeExploit.innerHTML = `🔥 ${escapeHtml(expStatus)}`;

    const actSummary = item.action_summary || 'APPLY VENDOR MITIGATION';
    badgeAction.innerHTML = `⚡ ${escapeHtml(actSummary)}`;

    // Detected Tech Stack & Ecosystem Pills
    if (dossierTechPills) {
      dossierTechPills.innerHTML = '';
      if (item.ecosystem) {
        const ecoPill = document.createElement('span');
        ecoPill.className = 'tech-pill eco-pill';
        ecoPill.textContent = `[ ECOSYSTEM: ${item.ecosystem} ]`;
        dossierTechPills.appendChild(ecoPill);
      }
      const tags = Array.isArray(item.tech_tags) ? item.tech_tags : [];
      tags.forEach(tag => {
        const pill = document.createElement('span');
        const tagLower = tag.toLowerCase();
        if (tagLower.includes('kernel') || tagLower.includes('bsd') || tagLower.includes('windows nt') || tagLower.includes('xnu')) {
          pill.className = 'tech-pill kernel-pill';
          pill.textContent = `[ CORE: ${tag} ]`;
        } else if (tagLower.includes('openssl') || tagLower.includes('glibc') || tagLower.includes('curl') || tagLower.includes('sqlite') || tagLower.includes('nginx') || tagLower.includes('apache')) {
          pill.className = 'tech-pill lib-pill';
          pill.textContent = `[ PKG: ${tag} ]`;
        } else {
          pill.className = 'tech-pill';
          pill.textContent = `[ STACK: ${tag} ]`;
        }
        pill.style.cursor = 'pointer';
        pill.title = `Click to filter by ${tag}`;
        pill.addEventListener('click', () => {
          if (state.techTag.toLowerCase() === tag.toLowerCase()) {
            state.techTag = '';
          } else {
            state.techTag = tag;
          }
          state.page = 1;
          fetchVulnerabilities();
          renderEcosystemTelemetry();
        });
        dossierTechPills.appendChild(pill);
      });
    }

    // Ransomware alert banner
    if (item.ransomware_campaign === 1) {
      dossierRansomwareBanner.innerHTML = `
        <div class="ransomware-alert">
          <span>🚨 CISA INTEL: EXPLOITED BY KNOWN RANSOMWARE CAMPAIGNS</span>
        </div>
      `;
    } else {
      dossierRansomwareBanner.innerHTML = '';
    }

    // Dynamic Attack Kill Chain Matrix
    renderKillChain(item);

    // 2. Tier 1: Human-First Overview
    dossierTldr.textContent = item.executive_summary || item.description || 'No executive summary available.';

    // Action Checklist
    dossierChecklist.innerHTML = '';
    const primaryAction = item.required_action || 'Apply vendor security updates immediately.';
    const item1 = document.createElement('div');
    item1.className = 'checklist-item';
    item1.innerHTML = `
      <span class="checklist-icon">⚡</span>
      <div class="checklist-content">
        <strong>PRIMARY ACTION:</strong> ${escapeHtml(primaryAction)}
      </div>
    `;
    dossierChecklist.appendChild(item1);

    if (item.remediation_notes) {
      let cleanNotes = item.remediation_notes;
      cleanNotes = cleanNotes.replace(/Federal Mandate Due Date:\s*[\d-]+(\s*\|\s*)?/i, '');
      cleanNotes = cleanNotes.replace(/Vendor Advisory \/ CISA Guidance:\s*/i, '');
      cleanNotes = cleanNotes.trim();

      if (cleanNotes) {
        const item2 = document.createElement('div');
        item2.className = 'checklist-item';
        item2.innerHTML = `
          <span class="checklist-icon">✓</span>
          <div class="checklist-content">
            <strong>MITIGATION GUIDANCE:</strong> ${convertUrlsToSmartPills(cleanNotes)}
          </div>
        `;
        dossierChecklist.appendChild(item2);
      }
    }

    if (item.due_date) {
      dossierDueTag.textContent = `DUE: ${item.due_date}`;
      const item3 = document.createElement('div');
      item3.className = 'checklist-item';
      item3.innerHTML = `
        <span class="checklist-icon">⏰</span>
        <div class="checklist-content" style="color: #FCD34D;">
          <strong>FEDERAL MANDATE DEADLINE:</strong> Remediation required by <span class="mono-font">${escapeHtml(item.due_date)}</span>.
        </div>
      `;
      dossierChecklist.appendChild(item3);
    } else {
      dossierDueTag.textContent = 'MANDATORY ACTION';
    }

    // Curated Threat Intelligence & Deep Reads
    dossierCuratedCards.innerHTML = '';
    const articles = (item.articles && item.articles.length > 0) ? item.articles : [
      {
        badge: '📰 News & Incident',
        domain: 'bleepingcomputer.com',
        title: `BleepingComputer: Threat Intel Coverage & Weaponization Analysis for ${item.cve_id}`,
        url: `https://www.bleepingcomputer.com/tag/${item.cve_id.toLowerCase()}/`
      },
      {
        badge: '🔬 Deep Analysis',
        domain: 'cisa.gov',
        title: `${item.vendor} Security Advisory & Vulnerability Kill Chain (${item.cve_id})`,
        url: `https://www.cisa.gov/news-events/cybersecurity-advisories?search=${item.cve_id}`
      },
      {
        badge: '🛠️ Advisory / Spec',
        domain: 'nvd.nist.gov',
        title: `NIST NVD Official Vulnerability Dossier (${item.cve_id})`,
        url: `https://nvd.nist.gov/vuln/detail/${item.cve_id}`
      }
    ];

    articles.forEach(art => {
      const card = document.createElement('a');
      card.className = 'intel-card';
      card.href = art.url;
      card.target = '_blank';
      card.rel = 'noopener noreferrer';
      card.innerHTML = `
        <div class="intel-card-top">
          <span class="intel-badge">${escapeHtml(art.badge || '📰 Intel')}</span>
          <span class="intel-domain">${escapeHtml(art.domain || 'external')}</span>
        </div>
        <div class="intel-title">
          <span>${escapeHtml(art.title)}</span>
          <span class="intel-arrow">↗</span>
        </div>
      `;
      dossierCuratedCards.appendChild(card);
    });

    // 3. Tier 2: Pro Inspector
    const epssPct = (item.epss_score * 100).toFixed(1);
    dossierEpssVal.textContent = epssPct + '%';
    dossierEpssBar.style.width = epssPct + '%';

    dossierEpssBar.className = 'epss-bar-fill';
    if (item.epss_score >= 0.80) {
      dossierEpssBar.classList.add('critical');
      dossierEpssRiskText.textContent = 'CRITICAL EXPLOITATION PROBABILITY';
      dossierEpssRiskText.style.color = 'var(--crimson)';
      dossierEpssVal.style.color = 'var(--crimson)';
    } else if (item.epss_score >= 0.50) {
      dossierEpssBar.classList.add('high');
      dossierEpssRiskText.textContent = 'HIGH EXPLOITATION PROBABILITY';
      dossierEpssRiskText.style.color = 'var(--orange)';
      dossierEpssVal.style.color = 'var(--orange)';
    } else {
      dossierEpssRiskText.textContent = 'NOMINAL PROBABILITY';
      dossierEpssRiskText.style.color = 'var(--sky-bright)';
      dossierEpssVal.style.color = 'var(--sky-bright)';
    }

    dossierEpssPercentile.textContent = `Percentile: ${Math.round(item.epss_percentile * 100)}th`;

    dossierVendor.textContent = item.vendor || '-';
    dossierProduct.textContent = item.product || '-';

    if (item.cwe_id && item.cwe_id.startsWith('CWE-')) {
      const cweNum = item.cwe_id.replace('CWE-', '');
      dossierCwe.innerHTML = `<a href="https://cwe.mitre.org/data/definitions/${cweNum}.html" target="_blank" style="color: var(--sky-bright); text-decoration: none;">${item.cwe_id} ↗</a>`;
    } else {
      dossierCwe.textContent = item.cwe_id || 'N/A';
    }
    dossierCweDesc.textContent = item.cwe_description || 'Common software security weakness categorized by MITRE.';

    dossierCvss.innerHTML = `${item.score.toFixed(1)} <span style="color: var(--text-dim); font-size: 0.65rem;">(${item.severity})</span>`;
    dossierVectorStr.textContent = item.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    dossierVector.textContent = item.vector || 'NETWORK / REMOTE';
    dossierDate.textContent = item.date_added || '-';
    dossierDesc.textContent = item.description || 'No detailed technical kill chain available.';

    btnNist.href = `https://nvd.nist.gov/vuln/detail/${item.cve_id}`;
  }

  function clearDossier() {
    dossierCveId.textContent = '-';
    dossierTargetSub.textContent = 'Select a record from live matrix';
    dossierRansomwareBanner.innerHTML = '';
    if (dossierTechPills) {
      dossierTechPills.innerHTML = '';
    }
    if (dossierKillchainFlow) {
      dossierKillchainFlow.innerHTML = `
        <div style="width: 100%; text-align: center; padding: 0.5rem; color: var(--text-dim); font-size: 0.72rem;">
          Select a vulnerability to map attack kill chain pathway
        </div>
      `;
    }
    dossierTldr.textContent = 'Select any vulnerability from the threat matrix to inspect an executive plain-English summary.';
    dossierChecklist.innerHTML = '';
    dossierCuratedCards.innerHTML = '';
    dossierEpssVal.textContent = '0.0%';
    dossierEpssBar.style.width = '0%';
    dossierVendor.textContent = '-';
    dossierProduct.textContent = '-';
    dossierCwe.textContent = '-';
    dossierCweDesc.textContent = '-';
    dossierCvss.textContent = '-';
    dossierVectorStr.textContent = '-';
    dossierVector.textContent = '-';
    dossierDate.textContent = '-';
    dossierDesc.textContent = '-';
  }

  function updatePagination() {
    const start = state.total === 0 ? 0 : (state.page - 1) * state.limit + 1;
    const end = Math.min(state.page * state.limit, state.total);
    paginationSummary.textContent = `Showing ${formatNumber(start)}-${formatNumber(end)} of ${formatNumber(state.total)}`;
    pageIndicator.textContent = `PAGE ${state.page} / ${state.totalPages}`;

    btnPrevPage.disabled = state.page <= 1;
    btnNextPage.disabled = state.page >= state.totalPages;
  }

  // Global Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    const isInput = e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA';

    if (e.key === 'Escape') {
      if (isInput) {
        e.target.blur();
      }
      // Reset all active filters
      state.category = 'ALL';
      state.severity = 'ALL';
      state.ransomwareOnly = false;
      state.search = '';
      state.dateAdded = '';
      state.vector = '';
      state.epssTier = '';
      state.ecosystem = '';
      state.techTag = '';
      state.page = 1;

      searchInput.value = '';
      severitySelect.value = 'ALL';
      chipRansomware.classList.remove('active');
      filterChips.querySelectorAll('.chip-btn:not(#chipRansomware)').forEach(b => {
        b.classList.toggle('active', b.dataset.cat === 'ALL');
      });
      updateHeatmapFilterIndicator();

      fetchVulnerabilities();
      fetchStats();
      showToast('RESET ALL ACTIVE FILTERS');
      return;
    }

    if (isInput) return;

    if (e.key === 'ArrowDown' || e.key === 'j') {
      e.preventDefault();
      if (state.selectedIndex < state.items.length - 1) {
        selectRow(state.selectedIndex + 1);
      }
    } else if (e.key === 'ArrowUp' || e.key === 'k') {
      e.preventDefault();
      if (state.selectedIndex > 0) {
        selectRow(state.selectedIndex - 1);
      }
    } else if (e.key === '/') {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    } else if (e.key === 'p' || e.key === 'P') {
      e.preventDefault();
      if (tabTierHuman && tabTierPro) {
        const isHumanActive = tabTierHuman.classList.contains('active');
        if (isHumanActive) {
          tabTierPro.click();
        } else {
          tabTierHuman.click();
        }
      }
    }
  });

  // Copy CVE ID
  btnCopyCve.addEventListener('click', () => {
    const cve = dossierCveId.textContent;
    if (cve && cve !== '-') {
      navigator.clipboard.writeText(cve).then(() => {
        showToast(`COPIED ${cve} TO CLIPBOARD`);
      });
    }
  });

  // Filter Chips
  filterChips.addEventListener('click', (e) => {
    const btn = e.target.closest('.chip-btn');
    if (!btn) return;

    if (btn === chipRansomware) {
      state.ransomwareOnly = !state.ransomwareOnly;
      chipRansomware.classList.toggle('active', state.ransomwareOnly);
      state.page = 1;
      fetchVulnerabilities();
      return;
    }

    const cat = btn.dataset.cat;
    if (!cat) return;

    state.category = cat;
    state.page = 1;

    filterChips.querySelectorAll('.chip-btn:not(#chipRansomware)').forEach(b => {
      b.classList.toggle('active', b.dataset.cat === cat);
    });

    fetchVulnerabilities();
  });

  // EPSS Tier Filter Click Handler
  if (epssTierGroup) {
    epssTierGroup.addEventListener('click', (e) => {
      const btn = e.target.closest('.epss-tier-btn');
      if (!btn) return;
      const tier = btn.dataset.tier;
      if (state.epssTier === tier) {
        state.epssTier = '';
      } else {
        state.epssTier = tier;
      }
      state.page = 1;
      fetchVulnerabilities();
      fetchStats();
    });
  }

  // Multi-Ecosystem Telemetry Tab Switching
  if (ecoTabBar) {
    ecoTabBar.addEventListener('click', (e) => {
      const btn = e.target.closest('.eco-tab-btn');
      if (!btn) return;
      const tab = btn.dataset.tab;
      if (!tab || state.activeEcoTab === tab) return;

      state.activeEcoTab = tab;
      ecoTabBar.querySelectorAll('.eco-tab-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.tab === tab);
      });
      renderEcosystemTelemetry();
    });
  }

  // Attack Vector Filter Handling
  function handleVectorClick(vec) {
    if (state.vector === vec) {
      state.vector = '';
    } else {
      state.vector = vec;
    }
    state.page = 1;
    fetchVulnerabilities();
    fetchStats();
  }

  if (vectorSegmentedBar) {
    vectorSegmentedBar.addEventListener('click', (e) => {
      const seg = e.target.closest('.segment-fill');
      if (seg && seg.dataset.vec) {
        handleVectorClick(seg.dataset.vec);
      }
    });
  }

  if (metricsVectorList) {
    metricsVectorList.addEventListener('click', (e) => {
      const pill = e.target.closest('.vector-pill');
      if (pill && pill.dataset.vec) {
        handleVectorClick(pill.dataset.vec);
      }
    });
  }

  // Clear Date Filter
  if (btnClearDateFilter) {
    btnClearDateFilter.addEventListener('click', () => {
      state.dateAdded = '';
      state.page = 1;
      updateHeatmapFilterIndicator();
      fetchVulnerabilities();
      fetchStats();
    });
  }

  // Search Input with Debounce
  let searchTimer;
  searchInput.addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.search = e.target.value.trim();
      state.page = 1;
      fetchVulnerabilities();
    }, 300);
  });

  severitySelect.addEventListener('change', (e) => {
    state.severity = e.target.value;
    state.page = 1;
    fetchVulnerabilities();
  });

  sortSelect.addEventListener('change', (e) => {
    state.sort = e.target.value;
    state.page = 1;
    fetchVulnerabilities();
  });

  btnPrevPage.addEventListener('click', () => {
    if (state.page > 1) {
      state.page--;
      fetchVulnerabilities();
    }
  });

  btnNextPage.addEventListener('click', () => {
    if (state.page < state.totalPages) {
      state.page++;
      fetchVulnerabilities();
    }
  });

  // Tier Tab Switching
  if (tabTierHuman && tabTierPro) {
    tabTierHuman.addEventListener('click', () => {
      tabTierHuman.classList.add('active');
      tabTierPro.classList.remove('active');
      panelTierHuman.style.display = 'flex';
      panelTierPro.style.display = 'none';
    });

    tabTierPro.addEventListener('click', () => {
      tabTierPro.classList.add('active');
      tabTierHuman.classList.remove('active');
      panelTierHuman.style.display = 'none';
      panelTierPro.style.display = 'flex';
    });
  }

  // Feed Synchronization
  btnSync.addEventListener('click', async () => {
    if (state.isSyncing) return;
    state.isSyncing = true;
    btnSync.classList.add('spinning');
    btnSyncText.textContent = 'SYNCING...';
    showToast('⚡ CISA KEV INTEL SYNC IN PROGRESS...');

    try {
      const res = await fetch('/api/sync', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Sync failed');

      const poll = setInterval(async () => {
        try {
          await fetchStats();
          clearInterval(poll);
          state.isSyncing = false;
          btnSync.classList.remove('spinning');
          btnSyncText.textContent = 'SYNC FEED';
          showToast('✓ CTI FEED SYNCHRONIZED');
          fetchVulnerabilities();
        } catch (e) {
          console.error(e);
        }
      }, 3000);
    } catch (err) {
      state.isSyncing = false;
      btnSync.classList.remove('spinning');
      btnSyncText.textContent = 'SYNC FEED';
      showToast(`SYNC ERROR: ${err.message}`);
    }
  });

  // Initialize
  fetchStats();
  fetchVulnerabilities();
})();
