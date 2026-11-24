// ============================================================
// THREATLENS WEB APPLICATION & SIMULATED GMAIL CLIENT
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  let currentFolder = 'inbox';
  let selectedEmailId = null;
  let mailboxData = { inbox: [], quarantine: [], spam: [], trash: [] };
  let samplesList = [];

  // ── DOM References ──────────────────────────────────────────
  const folderButtons = document.querySelectorAll('.folder-btn');
  const emailContainer = document.getElementById('email-items-container');
  const viewerEmpty = document.getElementById('email-viewer-empty');
  const viewerContent = document.getElementById('email-viewer-content');
  const threatCardContainer = document.getElementById('injected-threat-card-container');
  const samplesContainer = document.getElementById('samples-list');
  const currentFolderTitle = document.getElementById('current-folder-title');
  const emailCountLabel = document.getElementById('email-count-label');

  // Counts
  const countInbox = document.getElementById('count-inbox');
  const countQuarantine = document.getElementById('count-quarantine');
  const countSpam = document.getElementById('count-spam');
  const countTrash = document.getElementById('count-trash');
  const quarantineCountBadge = document.getElementById('quarantine-count-badge');

  // Viewer fields
  const viewSubject = document.getElementById('view-subject');
  const viewFrom = document.getElementById('view-from');
  const viewTo = document.getElementById('view-to');
  const viewDate = document.getElementById('view-date');
  const viewAuthSummary = document.getElementById('view-auth-summary');
  const viewBody = document.getElementById('view-body');
  const viewAttachmentsBox = document.getElementById('view-attachments-box');
  const viewAttachmentsList = document.getElementById('view-attachments-list');

  // Modals
  const modalAudit = document.getElementById('modal-audit');
  const modalQuarantine = document.getElementById('modal-quarantine');
  const modalOAuth = document.getElementById('modal-oauth');

  // ── Initialize App ──────────────────────────────────────────
  init();

  async function init() {
    setupEventListeners();
    await loadSamples();
    await fetchMailbox();
    await fetchStatus();
    startLivePolling();
  }

  function setupEventListeners() {
    // Folder navigation
    folderButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        folderButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFolder = btn.dataset.folder;
        currentFolderTitle.textContent = btn.querySelector('.folder-name').textContent;
        renderEmailList();
      });
    });

    // Reset demo mailbox
    document.getElementById('btn-reset-demo').addEventListener('click', async () => {
      await fetch('/api/demo/mailbox/reset', { method: 'POST' });
      await fetchMailbox();
      showToast('Demo Mailbox Reset to Initial State');
    });

    // Modals
    document.getElementById('btn-open-audit-modal').addEventListener('click', () => {
      openModal(modalAudit);
      loadAuditLog();
    });
    document.getElementById('btn-open-quarantine-modal').addEventListener('click', () => {
      openModal(modalQuarantine);
      loadQuarantineManager();
    });
    document.getElementById('btn-open-oauth-modal').addEventListener('click', () => {
      openModal(modalOAuth);
      loadOAuthStatus();
    });

    document.querySelectorAll('.modal-close').forEach(btn => {
      btn.addEventListener('click', () => {
        const modalId = btn.dataset.close;
        const target = document.getElementById(modalId);
        if (target) closeModal(target);
      });
    });

    // OAuth Connect button
    document.getElementById('btn-connect-gmail').addEventListener('click', async () => {
      const clientId = document.getElementById('oauth-client-id').value;
      const clientSecret = document.getElementById('oauth-client-secret').value;
      if (clientId) {
        await fetch('/api/gmail/credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ clientId, clientSecret }),
        });
      }
      const res = await fetch('/api/gmail/auth-url');
      const data = await res.json();
      if (data.auth_url) {
        window.open(data.auth_url, '_blank');
      }
    });

    document.getElementById('btn-sync-gmail').addEventListener('click', async () => {
      const res = await fetch('/api/gmail/sync-now', { method: 'POST' });
      const data = await res.json();
      showToast(data.message || data.error);
      await fetchMailbox();
    });

    document.getElementById('btn-disconnect-gmail').addEventListener('click', async () => {
      await fetch('/api/gmail/disconnect', { method: 'POST' });
      showToast('Disconnected from Live Gmail. In Demo Mode.');
      loadOAuthStatus();
    });
  }

  // ── Load Sample Threat Injectors ─────────────────────────────
  async function loadSamples() {
    try {
      const res = await fetch('/api/demo/samples');
      const data = await res.json();
      samplesList = data.samples || [];

      samplesContainer.innerHTML = '';
      const icons = {
        'SAFE': '🟢',
        'PHISHING': '🎣',
        'BEC': '💼',
        'INVESTMENT_SCAM': '💰',
        'HARASSMENT': '⚠️',
        'MALICIOUS_MACRO': '☣️',
        'IP_BASED_URL': '🔗',
        'BRAND_IMPERSONATION': '🎭',
        'CREDENTIAL_HARVESTING': '🔓',
        'SPAM': '🚫',
      };

      for (const sample of samplesList) {
        const btn = document.createElement('button');
        btn.className = 'sample-btn';
        const icon = icons[sample.expected_category] || '✉️';
        btn.innerHTML = `
          <span class="sample-icon">${icon}</span>
          <span>${sample.subject.slice(0, 32)}…</span>
        `;
        btn.title = `Inject test threat: ${sample.expected_category} - ${sample.subject}`;
        btn.addEventListener('click', () => injectSample(sample.id));
        samplesContainer.appendChild(btn);
      }
    } catch (e) {
      samplesContainer.innerHTML = '<div class="text-muted">Failed to load samples</div>';
    }
  }

  async function injectSample(sampleId) {
    try {
      const res = await fetch('/api/demo/send-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_id: sampleId }),
      });
      const data = await res.json();
      await fetchMailbox();
      if (data.email) {
        selectEmail(data.email.id);
      }
      showToast(`Injected sample: ${data.email?.subject?.slice(0, 30)}`);
    } catch (e) {
      showToast('Failed to inject sample');
    }
  }

  // ── Fetch & Render Mailbox ──────────────────────────────────
  async function fetchMailbox() {
    try {
      const res = await fetch('/api/demo/mailbox');
      mailboxData = await res.json();

      // Update badge counters
      countInbox.textContent = mailboxData.inbox.length;
      countQuarantine.textContent = mailboxData.quarantine.length;
      countSpam.textContent = mailboxData.spam.length;
      countTrash.textContent = mailboxData.trash.length;
      quarantineCountBadge.textContent = mailboxData.quarantine.length;

      renderEmailList();
    } catch (err) {
      console.error('Mailbox fetch failed:', err);
    }
  }

  function renderEmailList() {
    const list = mailboxData[currentFolder] || [];
    emailCountLabel.textContent = `${list.length} message${list.length === 1 ? '' : 's'}`;

    if (list.length === 0) {
      emailContainer.innerHTML = `<div class="empty-state" style="height:200px"><p>No messages in ${currentFolder}</p></div>`;
      return;
    }

    emailContainer.innerHTML = '';
    for (const email of list) {
      const card = document.createElement('div');
      card.className = `email-list-card ${email.id === selectedEmailId ? 'selected' : ''}`;
      
      const inv = email.investigation;
      let threatPill = '';
      if (inv) {
        if (inv.is_threat) {
          const sevClass = inv.risk_score >= 80 ? 'critical' : inv.risk_score >= 50 ? 'high' : 'medium';
          threatPill = `<span class="threat-mini-pill ${sevClass}">🔴 ${inv.primary_category?.name || 'THREAT'} (${inv.risk_score})</span>`;
        } else {
          threatPill = `<span class="threat-mini-pill safe">🟢 SAFE</span>`;
        }
      }

      card.innerHTML = `
        <div class="email-card-top">
          <span class="email-card-sender">${esc(email.from_name || email.from_email || 'Unknown')}</span>
          <span class="email-card-date">${formatDate(email.date)}</span>
        </div>
        <div class="email-card-subject">${esc(email.subject)}</div>
        <div class="email-card-bottom">
          ${threatPill}
        </div>
      `;

      card.addEventListener('click', () => selectEmail(email.id));
      emailContainer.appendChild(card);
    }
  }

  // ── Select & Inspect Email ──────────────────────────────────
  function selectEmail(id) {
    selectedEmailId = id;
    renderEmailList();

    let found = null;
    for (const list of Object.values(mailboxData)) {
      found = list.find(e => e.id === id);
      if (found) break;
    }

    if (!found) return;

    viewerEmpty.classList.add('hidden');
    viewerContent.classList.remove('hidden');

    viewSubject.textContent = found.subject;
    viewFrom.textContent = `${found.from_name || ''} <${found.from_email || ''}>`;
    viewTo.textContent = found.to_email || 'You';
    viewDate.textContent = new Date(found.date).toLocaleString();
    viewAuthSummary.textContent = `SPF: ${found.spf || 'NONE'} | DKIM: ${found.dkim || 'NONE'} | DMARC: ${found.dmarc || 'NONE'}`;

    if (found.body_html) {
      viewBody.innerHTML = found.body_html;
    } else {
      viewBody.textContent = found.body_text || '(Empty Body)';
    }

    // Attachments
    if (found.attachments && found.attachments.length > 0) {
      viewAttachmentsBox.classList.remove('hidden');
      viewAttachmentsList.innerHTML = found.attachments.map(a => `
        <div class="att-chip">
          <span>📄</span>
          <strong>${esc(a.name || a.filename)}</strong>
          <span class="text-muted">(${Math.round((a.size || 1000) / 1024)} KB)</span>
        </div>
      `).join('');
    } else {
      viewAttachmentsBox.classList.add('hidden');
    }

    // ── Inject ThreatLens Security Card ────────────────────────
    renderThreatCard(found);
  }

  // ── Render Threat Card (Priority Order) ──────────────────────
  function renderThreatCard(email) {
    const inv = email.investigation;
    threatCardContainer.innerHTML = '';

    if (!inv) {
      threatCardContainer.innerHTML = `
        <div class="tl-loading" style="padding:16px;background:rgba(255,255,255,0.03);border-radius:10px;text-align:center">
          <div class="tl-spinner"></div>
          <span>Analysing email for threats…</span>
        </div>
      `;
      return;
    }

    const isThreat = inv.is_threat;
    const sevColor = inv.severity ? inv.severity.color : (isThreat ? '#FF2D55' : '#34C759');
    const cat = inv.primary_category;
    const parentName = cat?.parent?.name || '';
    const topEvidence = (inv.evidence || []).filter(e => e.severity !== 'SAFE').slice(0, 5);

    const actionBadgeMap = {
      'QUARANTINE': { text: '🔒 QUARANTINED', class: 'action-quarantine' },
      'SPAM': { text: '🧹 SPAM FILTERED', class: 'action-flag' },
      'FLAG': { text: '🚩 FLAGGED FOR REVIEW', class: 'action-flag' },
      'WARN': { text: '⚠️ SUSPICIOUS', class: 'action-warn' },
      'ALLOW': { text: '✅ ALLOWED IN INBOX', class: 'action-safe' },
    };

    const actionMeta = actionBadgeMap[inv.executed_action || inv.recommended_action] || actionBadgeMap['ALLOW'];

    const card = document.createElement('div');
    card.id = 'threatlens-card';
    card.className = isThreat ? 'tl-threat' : 'tl-safe';
    card.style.setProperty('--tl-severity-color', sevColor);

    if (isThreat && cat) {
      card.innerHTML = `
        <!-- HEADER -->
        <div class="tl-header">
          <span class="tl-header-icon">⚠️</span>
          <span class="tl-header-title">Threat Detected</span>
          <span class="tl-header-badge">ThreatLens AI Engine</span>
        </div>

        <!-- ① CATEGORY -->
        <div class="tl-category-section">
          <div class="tl-section-label">Classification</div>
          <div class="tl-primary-category">
            <span class="tl-cat-icon">${cat.icon || '⚠️'}</span>
            <div>
              <div class="tl-cat-name">${esc(cat.name.toUpperCase())}</div>
              ${parentName ? `<div class="tl-cat-parent">${esc(parentName)}</div>` : ''}
            </div>
          </div>
          <div class="tl-severity-pill" style="color: ${sevColor}">
            <div class="tl-severity-dot" style="background:${sevColor}; box-shadow: 0 0 6px ${sevColor}"></div>
            ${inv.severity?.label || 'HIGH'}
          </div>
        </div>

        <!-- ② RISK & CONFIDENCE -->
        <div class="tl-metrics-row">
          <div class="tl-metric">
            <div class="tl-metric-label">Risk Score</div>
            <div class="tl-metric-value" style="color:${sevColor}">${inv.risk_score}</div>
            <div class="tl-metric-sub">/ 100</div>
            <div class="tl-risk-bar">
              <div class="tl-risk-fill" style="width:${inv.risk_score}%; background:${sevColor}"></div>
            </div>
          </div>
          <div class="tl-metric">
            <div class="tl-metric-label">Confidence</div>
            <div class="tl-metric-value" style="color:#64D2FF">${inv.confidence_pct}%</div>
            <div class="tl-metric-sub">analytic certainty</div>
            <div class="tl-risk-bar">
              <div class="tl-risk-fill" style="width:${inv.confidence_pct}%; background:#64D2FF"></div>
            </div>
          </div>
        </div>

        <!-- ③ WHY THIS EMAIL WAS CLASSIFIED THIS WAY -->
        <div class="tl-why-section">
          <div class="tl-why-label">Why this email was classified as a threat</div>
          <div class="tl-why-text">${esc(inv.explanation)}</div>
        </div>

        <!-- ④ EVIDENCE (VERIFIED ONLY) -->
        <div class="tl-evidence-section">
          <div class="tl-evidence-label">Verified Evidence (${topEvidence.length})</div>
          <div class="tl-evidence-list">
            ${topEvidence.length > 0 ? topEvidence.map(e => `
              <div class="tl-evidence-item">
                <span class="tl-ev-icon">✓</span>
                <span class="tl-ev-text">${esc(e.finding)}</span>
              </div>
            `).join('') : '<div class="tl-evidence-item"><span class="tl-ev-text">Forensic inspection completed</span></div>'}
          </div>
        </div>

        <!-- ⑤ ACTION EXECUTED -->
        <div class="tl-action-section">
          <div class="tl-action-badge ${actionMeta.class}">${actionMeta.text}</div>
          <div class="tl-action-desc">${esc(inv.policy_reason || 'Policy applied based on verified risk evaluation.')}</div>
        </div>

        <!-- ⑥ FULL INVESTIGATION CTA -->
        <div class="tl-footer">
          <button class="tl-investigate-btn">🔬 View Full Investigation</button>
        </div>
      `;
    } else {
      // Safe email card
      card.innerHTML = `
        <div class="tl-header">
          <span class="tl-header-icon">🟢</span>
          <span class="tl-header-title">No Significant Threats Detected</span>
          <span class="tl-header-badge">ThreatLens AI Engine</span>
        </div>

        <div class="tl-why-section" style="margin-top:12px">
          <div class="tl-why-text">${esc(inv.explanation)}</div>
        </div>

        <div class="tl-evidence-section">
          <div class="tl-evidence-label">Verified Safety Indicators</div>
          <div class="tl-evidence-list">
            <div class="tl-evidence-item"><span class="tl-ev-icon" style="color:#34C759">✓</span><span class="tl-ev-text">Cryptographic email authentication passed</span></div>
            <div class="tl-evidence-item"><span class="tl-ev-icon" style="color:#34C759">✓</span><span class="tl-ev-text">Sender identity is consistent with domain</span></div>
            <div class="tl-evidence-item"><span class="tl-ev-icon" style="color:#34C759">✓</span><span class="tl-ev-text">Hyperlinks resolve to verified destination hosts</span></div>
          </div>
        </div>

        <div class="tl-action-section">
          <div class="tl-action-badge action-safe">✅ ALLOWED IN INBOX</div>
        </div>

        <div class="tl-footer">
          <button class="tl-investigate-btn">🔬 View Full Investigation</button>
        </div>
      `;
    }

    // Attach Forensic Modal View
    const btn = card.querySelector('.tl-investigate-btn');
    if (btn) {
      btn.addEventListener('click', () => {
        if (window.ForensicView) {
          window.ForensicView.open(inv);
        }
      });
    }

    threatCardContainer.appendChild(card);
  }

  // ── Modals Logic ────────────────────────────────────────────
  function openModal(el) { el.classList.remove('hidden'); }
  function closeModal(el) { el.classList.add('hidden'); }

  async function loadAuditLog() {
    try {
      const res = await fetch('/api/audit-log');
      const data = await res.json();
      const tbody = document.getElementById('audit-table-body');
      if (!data.audit_log || data.audit_log.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No actions recorded yet</td></tr>';
        return;
      }

      tbody.innerHTML = data.audit_log.map(a => `
        <tr>
          <td style="font-family:var(--font-mono);font-size:10px">${new Date(a.timestamp).toLocaleTimeString()}</td>
          <td><strong>${esc(a.executed_action)}</strong></td>
          <td>${esc(a.threat_category)}</td>
          <td><span style="color:${a.risk_score >= 60 ? '#ff2d55' : '#34c759'}">${a.risk_score}/100</span></td>
          <td>${esc((a.subject || '').slice(0, 25))}</td>
          <td style="font-size:11px;color:var(--text-muted)">${esc(a.reason || '')}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
    }
  }

  async function loadQuarantineManager() {
    try {
      const res = await fetch('/api/quarantine');
      const data = await res.json();
      const listContainer = document.getElementById('quarantine-manager-list');
      if (!data.items || data.items.length === 0) {
        listContainer.innerHTML = '<div class="empty-state"><p>No messages currently held in quarantine</p></div>';
        return;
      }

      listContainer.innerHTML = data.items.map(item => `
        <div class="q-item-card">
          <div class="q-item-info">
            <div class="q-item-subject">🔒 ${esc(item.email?.subject || 'Quarantined Message')}</div>
            <div class="q-item-meta">
              From: ${esc(item.email?.from_email || item.email?.from_raw || 'Unknown')} ·
              Risk: ${item.investigation?.risk_score}/100 ·
              Held at: ${new Date(item.timestamp).toLocaleString()}
            </div>
          </div>
          <button class="q-item-action-btn" onclick="window.restoreEmail('${item.id}')">
            ${item.restored ? '✅ Restored' : '↩️ Restore to Inbox'}
          </button>
        </div>
      `).join('');
    } catch (e) {
      console.error(e);
    }
  }

  window.restoreEmail = async (id) => {
    try {
      const res = await fetch('/api/quarantine/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_id: id }),
      });
      const data = await res.json();
      showToast(data.message || 'Restored message');
      await fetchMailbox();
      loadQuarantineManager();
    } catch (e) {
      showToast('Error restoring message');
    }
  };

  async function loadOAuthStatus() {
    try {
      const res = await fetch('/api/gmail/status');
      const data = await res.json();
      const box = document.getElementById('oauth-status-info');
      const modePill = document.getElementById('current-mode-pill');

      if (data.is_authenticated) {
        box.innerHTML = `
          <div style="color:#34C759;font-weight:700">🟢 Connected to Gmail API</div>
          <div style="margin-top:4px">Account: ${esc(data.account_email)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Labels ThreatLens/Quarantine and ThreatLens/Safe are active.</div>
        `;
        modePill.textContent = 'LIVE GMAIL ACTIVE';
        modePill.className = 'mode-pill live';
      } else {
        box.innerHTML = `
          <div style="color:#FF9500;font-weight:700">🟠 Demo Simulation Mode Active</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Connect your Google Cloud OAuth credentials to process live Gmail messages.</div>
        `;
        modePill.textContent = 'DEMO SIMULATION';
        modePill.className = 'mode-pill demo';
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      if (data.monitoring?.active) {
        document.getElementById('soc-status-text').textContent = '🟢 PROTECTION ACTIVE (24/7 Monitoring)';
      }
    } catch (e) {}
  }

  function startLivePolling() {
    setInterval(() => {
      fetchMailbox();
      fetchStatus();
    }, 15000);
  }

  // ── Helpers ─────────────────────────────────────────────────
  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function formatDate(d) {
    if (!d) return '';
    const date = new Date(d);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function showToast(msg) {
    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed; bottom: 24px; right: 24px; background: #1c2230;
      border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 12px 18px;
      border-radius: 8px; font-size: 12px; font-weight: 600; z-index: 10000;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5); transition: all 0.3s ease;
    `;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }
});
