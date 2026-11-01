(function () {
  'use strict';

  // State Management
  const state = {
    category: 'ALL',
    severity: 'ALL',
    ransomwareOnly: false,
    search: '',
    sort: 'date_desc',
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
  const metricEpssCrit = document.getElementById('metricEpssCrit');
  const metricEpssHigh = document.getElementById('metricEpssHigh');
  const metricEpssLow = document.getElementById('metricEpssLow');
  const metricsVendorsList = document.getElementById('metricsVendorsList');
  const metricsVectorList = document.getElementById('metricsVectorList');

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

      hudTotal.textContent = formatNumber(data.total_records);
      hudCritical.textContent = formatNumber(data.critical_count);
      hudRansomware.textContent = formatNumber(data.ransomware_count);
      hudAvgEPSS.textContent = (data.avg_epss * 100).toFixed(1) + '%';
      hudLastSync.textContent = data.last_sync || 'NEVER';

      // EPSS Distribution
      metricEpssCrit.textContent = formatNumber(data.epss_critical);
      metricEpssHigh.textContent = formatNumber(data.epss_high);
      metricEpssLow.textContent = formatNumber(data.epss_low);

      // Top Targeted Vendors Leaderboard
      metricsVendorsList.innerHTML = '';
      (data.top_vendors || []).forEach(v => {
        const item = document.createElement('div');
        item.className = 'vendor-item';
        item.innerHTML = `<span>${v.vendor}</span> <span style="font-weight: 700; color: var(--cyan);">${formatNumber(v.count)}</span>`;
        item.addEventListener('click', () => {
          searchInput.value = v.vendor;
          state.search = v.vendor;
          state.page = 1;
          fetchVulnerabilities();
        });
        metricsVendorsList.appendChild(item);
      });

      // Attack Vector Breakdown
      metricsVectorList.innerHTML = '';
      (data.vector_counts || []).forEach(vc => {
        const item = document.createElement('div');
        item.className = 'stat-row';
        item.innerHTML = `<span style="font-size: 0.65rem; color: var(--text-dim);">${vc.vector}</span> <span style="font-weight: 700;">${formatNumber(vc.count)}</span>`;
        metricsVectorList.appendChild(item);
      });
    } catch (err) {
      console.error('Failed to load stats:', err);
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

      // EPSS display
      const epssPct = (item.epss_score * 100).toFixed(1) + '%';
      let epssColor = 'var(--text-main)';
      if (item.epss_score >= 0.80) epssColor = 'var(--crimson)';
      else if (item.epss_score >= 0.50) epssColor = 'var(--orange)';

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
        <td class="epss-cell" style="color: ${epssColor};">${epssPct}</td>
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

  function displayDossier(item) {
    dossierCveId.textContent = item.cve_id;
    dossierTargetSub.textContent = `${item.product || 'Unknown Product'} (${item.vendor || 'Unknown Vendor'})`;

    // 1. 3 Instant Badges
    // Urgency Badge
    const urg = item.urgency || 'SCHEDULE MAINTENANCE';
    badgeUrgency.textContent = `URGENCY: ${urg}`;
    if (urg.includes('IMMEDIATE')) {
      badgeUrgency.className = 'instant-badge badge-urgency';
    } else if (urg.includes('SCHEDULE')) {
      badgeUrgency.className = 'instant-badge badge-urgency yellow';
    } else {
      badgeUrgency.className = 'instant-badge badge-urgency blue';
    }

    // In The Wild Badge
    const expStatus = item.exploit_status || 'ACTIVE IN WILD';
    badgeExploit.innerHTML = `🔥 ${escapeHtml(expStatus)}`;

    // Action Badge
    const actSummary = item.action_summary || 'APPLY VENDOR MITIGATION';
    badgeAction.innerHTML = `⚡ ${escapeHtml(actSummary)}`;

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

    // 2. Tier 1: Human-First Overview
    // Executive Summary (TL;DR)
    dossierTldr.textContent = item.executive_summary || item.description || 'No executive summary available.';

    // Action Checklist (Clean bulleted checklist with smart link pills)
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

    // Curated Threat Intelligence & Deep Reads (2-3 Intel Cards)
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
    // EPSS probability meter
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
      dossierEpssRiskText.style.color = 'var(--cyan)';
      dossierEpssVal.style.color = 'var(--cyan)';
    }

    dossierEpssPercentile.textContent = `Percentile: ${Math.round(item.epss_percentile * 100)}th`;

    // Pro Metadata fields
    dossierVendor.textContent = item.vendor || '-';
    dossierProduct.textContent = item.product || '-';

    // CWE with link and description
    if (item.cwe_id && item.cwe_id.startsWith('CWE-')) {
      const cweNum = item.cwe_id.replace('CWE-', '');
      dossierCwe.innerHTML = `<a href="https://cwe.mitre.org/data/definitions/${cweNum}.html" target="_blank" style="color: var(--cyan); text-decoration: none;">${item.cwe_id} ↗</a>`;
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

  // Keyboard Navigation
  window.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;

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
