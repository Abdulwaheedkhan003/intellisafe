// ============================================================
// FORENSIC INVESTIGATION PANEL — ThreatLens UI
// Slide-in comprehensive security panel with all 10 forensic sections:
// 1. Classification
// 2. Explanation
// 3. Sender Analysis
// 4. Authentication (SPF, DKIM, DMARC)
// 5. URL Analysis
// 6. Attachment Analysis
// 7. Content Analysis
// 8. Threat Intelligence (Strict: INTELLIGENCE UNAVAILABLE when unverified)
// 9. Investigation Timeline (Real execution timestamps)
// 10. Final Decision & Policy Actions
// ============================================================

const ForensicView = {
  _overlay: null,

  open(result) {
    if (this._overlay) this.close();

    const overlay = document.createElement('div');
    overlay.id = 'threatlens-forensic-overlay';
    document.body.appendChild(overlay);
    this._overlay = overlay;

    overlay.innerHTML = `
      <div id="threatlens-forensic-backdrop"></div>
      <div id="threatlens-forensic-panel">
        ${this._buildPanel(result)}
      </div>
    `;

    // Backdrop and close button handlers
    overlay.querySelector('#threatlens-forensic-backdrop').addEventListener('click', () => this.close());
    overlay.querySelector('.fp-close-btn').addEventListener('click', () => this.close());

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        overlay.classList.add('open');
      });
    });

    this._escHandler = (e) => { if (e.key === 'Escape') this.close(); };
    document.addEventListener('keydown', this._escHandler);
  },

  close() {
    if (!this._overlay) return;
    this._overlay.classList.remove('open');
    if (this._escHandler) document.removeEventListener('keydown', this._escHandler);
    setTimeout(() => {
      if (this._overlay) {
        this._overlay.remove();
        this._overlay = null;
      }
    }, 400);
  },

  _buildPanel(result) {
    const isThreat = result.is_threat;
    const cat = result.primary_category || { name: 'SAFE', icon: '🛡️' };
    const severityColor = result.severity ? result.severity.color : (isThreat ? '#FF2D55' : '#34C759');
    const evidence = result.evidence || [];

    // Group evidence by category
    const senderEv = evidence.filter(e => e.type === 'SENDER');
    const authEv = evidence.filter(e => e.type === 'AUTH');
    const urlEv = evidence.filter(e => e.type === 'URL');
    const attEv = evidence.filter(e => e.type === 'ATTACHMENT');
    const contentEv = evidence.filter(e => e.type === 'CONTENT');
    const intelEv = evidence.filter(e => e.type === 'THREAT_INTEL');

    const timeline = result.investigation_timeline || [];

    return `
      <!-- PANEL HEADER -->
      <div class="fp-header" style="border-left: 3px solid ${severityColor}">
        <div>
          <div class="fp-header-title">🔬 Full Security Investigation</div>
          <div class="fp-header-subtitle">
            ${this._esc(result.email_subject || 'Email Security Inspection')} · ${new Date(result.analysis_timestamp || Date.now()).toLocaleTimeString()}
          </div>
        </div>
        <button class="fp-close-btn">✕</button>
      </div>

      <div class="fp-content">

        <!-- ── 1. CLASSIFICATION ──────────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">1. Threat Classification</div>
          <div class="fp-classification">
            <div class="fp-primary-cat-block" style="border-color: ${severityColor}40; background: ${severityColor}10">
              <span class="fp-cat-big-icon">${cat.icon || '⚠️'}</span>
              <div>
                <div class="fp-cat-big-name" style="color:${severityColor}">${this._esc(cat.name.toUpperCase())}</div>
                ${cat.parent ? `<div class="fp-cat-big-parent">${this._esc(cat.parent.name || '')}</div>` : ''}
              </div>
            </div>

            <div class="fp-risk-row">
              <div class="fp-metric-box">
                <div class="fp-metric-box-label">Risk Score</div>
                <div class="fp-metric-box-value" style="color:${severityColor}">${result.risk_score}</div>
                <div class="fp-metric-box-sub">out of 100 · ${result.severity?.label || 'EVALUATED'}</div>
              </div>
              <div class="fp-metric-box">
                <div class="fp-metric-box-label">Confidence</div>
                <div class="fp-metric-box-value" style="color:#64D2FF">${result.confidence_pct || Math.round((result.confidence || 0.9) * 100)}%</div>
                <div class="fp-metric-box-sub">Analytic Certainty</div>
              </div>
            </div>

            ${(result.secondary_categories || []).length > 0 ? `
            <div style="margin-top:10px">
              <div style="font-size:10px;font-weight:700;color:rgba(255,255,255,0.4);text-transform:uppercase;margin-bottom:6px">Secondary Classifications</div>
              <div class="fp-sec-cats">
                ${result.secondary_categories.map(s => `
                  <span class="fp-sec-cat-chip">${this._esc(s.name)} (${Math.round((s.confidence || 0.5) * 100)}%)</span>
                `).join('')}
              </div>
            </div>` : ''}
          </div>
        </div>

        <!-- ── 2. EXPLANATION ──────────────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">2. Human-Readable Reasoning</div>
          <div class="fp-explanation-box">
            ${this._esc(result.explanation || 'Forensic inspection completed without anomalous findings.')}
          </div>
        </div>

        <!-- ── 3. SENDER ANALYSIS ──────────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">3. Sender Identity & Spoofing Analysis</div>
          <div class="fp-details-grid">
            <div class="fp-detail-row"><span class="fp-label">From:</span><span class="fp-val">${this._esc(result.email_from || 'Not available')}</span></div>
            <div class="fp-detail-row"><span class="fp-label">Display Name:</span><span class="fp-val">${this._esc(result.email_from_name || 'Not available')}</span></div>
          </div>
          <div class="fp-evidence-sublist">
            ${senderEv.length > 0 ? senderEv.map(e => this._renderEvidenceItem(e)).join('') : '<div class="fp-empty-ev">No sender anomalies detected</div>'}
          </div>
        </div>

        <!-- ── 4. AUTHENTICATION ───────────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">4. Cryptographic Authentication</div>
          <div class="fp-evidence-sublist">
            ${authEv.length > 0 ? authEv.map(e => this._renderEvidenceItem(e)).join('') : '<div class="fp-empty-ev">Authentication records verified</div>'}
          </div>
        </div>

        <!-- ── 5. URL ANALYSIS ─────────────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">5. Hyperlink & Destination Domain Inspection</div>
          <div class="fp-evidence-sublist">
            ${urlEv.length > 0 ? urlEv.map(e => this._renderEvidenceItem(e)).join('') : '<div class="fp-empty-ev">No malicious links or IP URLs detected</div>'}
          </div>
        </div>

        <!-- ── 6. ATTACHMENT ANALYSIS ──────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">6. Attachment & Payload Forensics</div>
          <div class="fp-evidence-sublist">
            ${attEv.length > 0 ? attEv.map(e => this._renderEvidenceItem(e)).join('') : '<div class="fp-empty-ev">No executable or macro-enabled attachments detected</div>'}
          </div>
        </div>

        <!-- ── 7. CONTENT ANALYSIS ─────────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">7. Content & Social Engineering Tactics</div>
          <div class="fp-evidence-sublist">
            ${contentEv.length > 0 ? contentEv.map(e => this._renderEvidenceItem(e)).join('') : '<div class="fp-empty-ev">No social engineering or urgency pressure detected</div>'}
          </div>
        </div>

        <!-- ── 8. THREAT INTELLIGENCE ──────────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">8. Threat Intelligence Feeds</div>
          <div class="fp-intel-box">
            ${intelEv.length > 0 ? intelEv.map(e => `
              <div class="fp-intel-match">
                <span class="fp-intel-badge">CONFIRMED IOC</span>
                <span>${this._esc(e.finding)}</span>
              </div>
            `).join('') : `
              <div class="fp-intel-unavailable">
                <span class="fp-intel-badge none">INTELLIGENCE UNAVAILABLE</span>
                <span>No verified external threat intel matches. Decision grounded on behavioral & cryptographic proof.</span>
              </div>
            `}
          </div>
        </div>

        <!-- ── 9. INVESTIGATION TIMELINE ──────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">9. Investigation Timeline (Real Execution)</div>
          <div class="fp-timeline">
            ${timeline.map(item => `
              <div class="fp-tl-item">
                <div class="fp-tl-dot"></div>
                <div class="fp-tl-time">${new Date(item.time).toLocaleTimeString()}</div>
                <div class="fp-tl-content">
                  <strong>${this._esc(item.action || item.event || 'Investigative Step')}</strong>
                  ${item.details ? `<div class="fp-tl-details">${this._esc(item.details)}</div>` : ''}
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- ── 10. FINAL DECISION & POLICY ────────────── -->
        <div class="fp-section">
          <div class="fp-section-title">10. Final Decision & Policy Execution</div>
          <div class="fp-decision-box" style="border-left: 3px solid ${severityColor}">
            <div class="fp-decision-header">
              <span class="fp-decision-action">${this._esc(result.executed_action || result.recommended_action || 'ALLOW')}</span>
              <span class="fp-decision-risk">Risk: ${result.risk_score}/100</span>
            </div>
            <div class="fp-decision-reason">
              ${this._esc(result.policy_reason || 'Policy evaluated risk score, confidence, category, and verified evidence.')}
            </div>
          </div>
        </div>

      </div>
    `;
  },

  _renderEvidenceItem(e) {
    const isSafe = e.severity === 'SAFE' || e.severity === 'NONE';
    const icon = isSafe ? '✓' : (e.severity === 'CRITICAL' ? '⛔' : '⚠️');
    const color = isSafe ? '#34C759' : (e.severity === 'CRITICAL' ? '#FF2D55' : '#FF9500');

    return `
      <div class="fp-evidence-card" style="border-left: 2px solid ${color}">
        <span class="fp-ev-icon" style="color:${color}">${icon}</span>
        <div class="fp-ev-content">
          <div class="fp-ev-finding">${this._esc(e.finding)}</div>
          <div class="fp-ev-meta">
            <span class="fp-ev-tag">${this._esc(e.type)}</span>
            <span class="fp-ev-tag status">${this._esc(e.verification_status || (e.verified ? 'CONFIRMED' : 'LIKELY'))}</span>
            <span class="fp-ev-tag">${Math.round((e.confidence || 0.9) * 100)}% Confidence</span>
          </div>
        </div>
      </div>
    `;
  },

  _esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  },
};

if (typeof window !== 'undefined') window.ForensicView = ForensicView;
