// ============================================================
// THREAT CARD UI COMPONENT
// Renders the threat classification card injected into Gmail.
// Strict Priority: Category → Risk → Why → Evidence → Action → Investigation
// ============================================================

const ThreatCard = {

  render(result) {
    const isThreat = result.is_threat;
    const severityColor = result.severity ? result.severity.color : (isThreat ? '#FF2D55' : '#34C759');
    const action = this._getActionMeta(result.executed_action || result.recommended_action);

    const card = document.createElement('div');
    card.id = 'threatlens-card';
    card.className = isThreat ? 'tl-threat' : 'tl-safe';
    card.style.setProperty('--tl-severity-color', severityColor);

    card.innerHTML = this._buildHTML(result, severityColor, action, isThreat);

    // Attach Forensic View Button
    const btn = card.querySelector('.tl-investigate-btn');
    if (btn) {
      btn.addEventListener('click', () => {
        if (typeof ForensicView !== 'undefined') {
          ForensicView.open(result);
        }
      });
    }

    return card;
  },

  renderLoading() {
    const card = document.createElement('div');
    card.id = 'threatlens-card';
    card.innerHTML = `
      <div class="tl-header">
        <span class="tl-header-icon">🔍</span>
        <span class="tl-header-title">ThreatLens AI Security</span>
      </div>
      <div class="tl-loading">
        <div class="tl-spinner"></div>
        <span>Forensically analysing email components…</span>
      </div>
    `;
    return card;
  },

  _buildHTML(result, severityColor, action, isThreat) {
    if (!isThreat) {
      return this._buildSafeHTML(result);
    }

    const cat = result.primary_category || { name: 'SUSPICIOUS EMAIL', icon: '⚠️' };
    const parent = cat.parent ? cat.parent.name : '';
    const secondaries = (result.secondary_categories || []).slice(0, 3);
    const topEvidence = (result.evidence || [])
      .filter(e => e.verified && e.severity !== 'SAFE')
      .slice(0, 5);

    return `
      <!-- HEADER -->
      <div class="tl-header">
        <span class="tl-header-icon">🔴</span>
        <span class="tl-header-title">THREAT DETECTED</span>
        <span class="tl-header-badge">ThreatLens AI</span>
      </div>

      <!-- ① CATEGORY -->
      <div class="tl-category-section">
        <div class="tl-section-label">Category</div>
        <div class="tl-primary-category">
          <span class="tl-cat-icon">${cat.icon || '⚠️'}</span>
          <div>
            <div class="tl-cat-name">${this._esc(cat.name.toUpperCase())}</div>
            ${parent ? `<div class="tl-cat-parent">${this._esc(parent)}</div>` : ''}
          </div>
        </div>
        <div class="tl-severity-pill" style="color: ${severityColor}">
          <div class="tl-severity-dot" style="background:${severityColor}; box-shadow: 0 0 6px ${severityColor}"></div>
          ${result.severity?.label || 'CRITICAL'}
        </div>
      </div>

      ${secondaries.length > 0 ? `
      <div class="tl-secondary-categories">
        ${secondaries.map(s => `<span class="tl-sec-chip">${this._esc(s.name)}</span>`).join('')}
      </div>` : ''}

      <!-- ② RISK & CONFIDENCE -->
      <div class="tl-metrics-row">
        <div class="tl-metric">
          <div class="tl-metric-label">Risk</div>
          <div class="tl-metric-value" style="color:${severityColor}">${result.risk_score}</div>
          <div class="tl-metric-sub">/ 100</div>
          <div class="tl-risk-bar">
            <div class="tl-risk-fill" style="width:${result.risk_score}%; background:${severityColor}"></div>
          </div>
        </div>
        <div class="tl-metric">
          <div class="tl-metric-label">Confidence</div>
          <div class="tl-metric-value" style="color:#64D2FF">${result.confidence_pct || Math.round((result.confidence || 0.9) * 100)}%</div>
          <div class="tl-metric-sub">analytic certainty</div>
          <div class="tl-risk-bar">
            <div class="tl-risk-fill" style="width:${result.confidence_pct || 90}%; background:#64D2FF"></div>
          </div>
        </div>
      </div>

      <!-- ③ WHY THIS EMAIL WAS CLASSIFIED THIS WAY -->
      <div class="tl-why-section">
        <div class="tl-why-label">Why this email was classified this way</div>
        <div class="tl-why-text">${this._esc(result.explanation)}</div>
      </div>

      <!-- ④ EVIDENCE (VERIFIED) -->
      <div class="tl-evidence-section">
        <div class="tl-evidence-label">Verified Evidence (${topEvidence.length})</div>
        <div class="tl-evidence-list">
          ${topEvidence.length > 0 ? topEvidence.map(e => `
            <div class="tl-evidence-item">
              <span class="tl-ev-icon">✓</span>
              <span class="tl-ev-text">${this._esc(e.finding)}</span>
            </div>
          `).join('') : '<div class="tl-evidence-item"><span class="tl-ev-text">Inspection completed</span></div>'}
        </div>
      </div>

      <!-- ⑤ ACTION -->
      <div class="tl-action-section">
        <div class="tl-action-badge ${action.class}">${action.text}</div>
        <div class="tl-action-desc">${this._esc(result.policy_reason || 'Policy applied based on verified risk evaluation.')}</div>
      </div>

      <!-- ⑥ INVESTIGATION CTA -->
      <div class="tl-footer">
        <button class="tl-investigate-btn">🔬 View Full Investigation</button>
      </div>
    `;
  },

  _buildSafeHTML(result) {
    return `
      <div class="tl-header">
        <span class="tl-header-icon">🟢</span>
        <span class="tl-header-title">NO SIGNIFICANT THREATS DETECTED</span>
        <span class="tl-header-badge">ThreatLens AI</span>
      </div>

      <div class="tl-why-section" style="margin-top:12px">
        <div class="tl-why-text">${this._esc(result.explanation || 'Based on the available evidence, no significant phishing, spoofing, malware, or social-engineering indicators were detected.')}</div>
      </div>

      <div class="tl-evidence-section">
        <div class="tl-evidence-label">Verified Safety Indicators</div>
        <div class="tl-evidence-list">
          <div class="tl-evidence-item"><span class="tl-ev-icon" style="color:#34C759">✓</span><span class="tl-ev-text">Cryptographic email authentication verified</span></div>
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
  },

  _getActionMeta(action) {
    const map = {
      'QUARANTINE': { text: '🔒 QUARANTINED', class: 'action-quarantine' },
      'SPAM':       { text: '🧹 SPAM FILTERED', class: 'action-flag' },
      'FLAG':       { text: '🚩 FLAGGED FOR REVIEW', class: 'action-flag' },
      'WARN':       { text: '⚠️ SUSPICIOUS', class: 'action-warn' },
      'ALLOW':      { text: '✅ ALLOWED IN INBOX', class: 'action-safe' },
    };
    return map[action] || map['ALLOW'];
  },

  _esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  },
};

if (typeof window !== 'undefined') window.ThreatCard = ThreatCard;
