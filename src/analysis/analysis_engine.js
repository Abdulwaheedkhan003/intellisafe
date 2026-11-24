// ============================================================
// ANALYSIS ENGINE — Master pipeline
// Orchestrates all detectors, classifies against taxonomy,
// calculates risk, generates explanation, and produces the
// normalized AnalysisResult object.
// ============================================================

const AnalysisEngine = {

  // Signal → category affinity map
  // Each signal contributes to specific categories with a weight multiplier
  SIGNAL_CATEGORY_MAP: {
    // Auth failures
    'spf_fail':                   [['PHISHING',0.7],['DOMAIN_SPOOFING',1.0],['BEC',0.6]],
    'dkim_fail':                  [['PHISHING',0.6],['DOMAIN_SPOOFING',0.9]],
    'dmarc_fail':                 [['PHISHING',0.7],['DOMAIN_SPOOFING',1.0],['BEC',0.6]],
    // Sender signals
    'domain_mismatch':            [['PHISHING',0.8],['DOMAIN_SPOOFING',1.0],['BRAND_IMPERSONATION',0.8],['BEC',0.7]],
    'display_name_spoofing':      [['DISPLAY_NAME_SPOOFING',1.0],['PHISHING',0.5],['BEC',0.6]],
    'brand_impersonation':        [['BRAND_IMPERSONATION',1.0],['PHISHING',0.8],['CLOUD_SERVICE_IMPERSONATION',0.5]],
    'typosquatting':              [['TYPOSQUATTING',1.0],['LOOKALIKE_DOMAIN',0.8],['PHISHING',0.7]],
    'lookalike_domain':           [['LOOKALIKE_DOMAIN',1.0],['TYPOSQUATTING',0.7],['PHISHING',0.6]],
    'punycode_domain':            [['HOMOGRAPH_ATTACK',1.0],['PUNYCODE_URL',0.9],['PHISHING',0.6]],
    'executive_impersonation':    [['EXECUTIVE_IMPERSONATION',1.0],['BEC',0.9],['CEO_FRAUD',0.7]],
    'unusual_sender':             [['SUSPICIOUS_SENDER',0.8],['SUSPICIOUS_EMAIL',0.5]],
    // URL signals
    'fake_login_url':             [['CREDENTIAL_HARVESTING',1.0],['FAKE_LOGIN_PAGE',1.0],['PHISHING',0.9],['ACCOUNT_VERIFICATION_SCAM',0.7]],
    'credential_request':         [['CREDENTIAL_HARVESTING',1.0],['CREDENTIAL_HARVESTING_URL',0.9],['PHISHING',0.8],['CREDENTIAL_REQUEST',0.8]],
    'credential_harvesting':      [['CREDENTIAL_HARVESTING',1.0],['PHISHING',0.8]],
    'obfuscated_url':             [['OBFUSCATED_URL',1.0],['MALICIOUS_REDIRECT',0.6],['PHISHING',0.5]],
    'ip_address_url':             [['IP_BASED_URL',1.0],['MALWARE_DELIVERY',0.5],['PHISHING',0.4]],
    'url_shortener':              [['URL_SHORTENER_ABUSE',1.0],['SUSPICIOUS_DOMAIN_URL',0.5]],
    'suspicious_link':            [['SUSPICIOUS_DOMAIN_URL',0.8],['PHISHING',0.4]],
    'suspicious_domain':          [['SUSPICIOUS_DOMAIN_URL',1.0],['NEWLY_REGISTERED_DOMAIN',0.5]],
    // Content signals
    'urgency_language':           [['PHISHING',0.5],['ACCOUNT_VERIFICATION_SCAM',0.6],['BEC',0.5],['SCAM',0.4]],
    'account_suspension_threat':  [['ACCOUNT_VERIFICATION_SCAM',1.0],['PHISHING',0.8],['LOGIN_VERIFICATION_SCAM',0.7]],
    'payment_request':            [['PAYMENT_FRAUD',0.9],['BEC',0.7],['INVOICE_FRAUD',0.6]],
    'financial_request':          [['PAYMENT_FRAUD',0.7],['BEC',0.7],['WIRE_TRANSFER_FRAUD',0.5]],
    'new_bank_account':           [['BANK_ACCOUNT_CHANGE',1.0],['PAYMENT_REDIRECTION',0.9],['INVOICE_FRAUD',0.7],['BEC',0.8]],
    'wire_transfer_request':      [['WIRE_TRANSFER_FRAUD',1.0],['BEC',0.8],['CEO_FRAUD',0.7]],
    'gift_card_request':          [['GIFT_CARD_SCAM',1.0],['CEO_FRAUD',0.6],['EXECUTIVE_IMPERSONATION',0.6]],
    'secrecy_request':            [['BEC',0.7],['CEO_FRAUD',0.6],['GIFT_CARD_SCAM',0.5]],
    'executive_reference':        [['CEO_FRAUD',0.7],['BEC',0.8],['EXECUTIVE_IMPERSONATION',0.7]],
    'extortion_keywords':         [['EXTORTION',1.0],['BLACKMAIL',0.7]],
    'blackmail_keywords':         [['BLACKMAIL',1.0],['EXTORTION',0.7]],
    'threat_language':            [['THREATENING_MESSAGE',1.0],['HARASSMENT',0.5],['EXTORTION',0.4]],
    'harassment_keywords':        [['HARASSMENT',1.0],['ABUSIVE_CONTENT',0.7]],
    'prize_claim':                [['PRIZE_SCAM',1.0],['SCAM',0.6]],
    'lottery_win_claim':          [['LOTTERY_SCAM',1.0],['PRIZE_SCAM',0.7]],
    'investment_offer':           [['INVESTMENT_SCAM',1.0],['SCAM',0.6]],
    'unrealistic_returns':        [['INVESTMENT_SCAM',0.9],['CRYPTO_SCAM',0.5]],
    'crypto_payment_request':     [['CRYPTO_SCAM',1.0],['EXTORTION',0.6]],
    'tax_authority_impersonation':[['TAX_SCAM',1.0],['GOVERNMENT_IMPERSONATION',0.8]],
    'government_agency_keyword':  [['GOVERNMENT_IMPERSONATION',0.8],['TAX_SCAM',0.5]],
    'bank_keyword':               [['FINANCIAL_INSTITUTION_IMPERSONATION',0.7],['PHISHING',0.5]],
    'cloud_service_keyword':      [['CLOUD_SERVICE_IMPERSONATION',0.7],['PHISHING',0.5]],
    'sensitive_info_request':     [['PERSONAL_INFO_HARVESTING',1.0],['IDENTITY_VERIFICATION_SCAM',0.7]],
    'payroll_change_request':     [['PAYROLL_FRAUD',1.0],['SALARY_DIVERSION',0.9],['BEC',0.7]],
    'scam_keywords':              [['SCAM',1.0],['FRAUD',0.6]],
    'scare_tactic':               [['TECH_SUPPORT_SCAM',0.8],['FAKE_SUPPORT_SCAM',0.6]],
    // Attachment signals
    'executable_attachment':      [['EXECUTABLE_ATTACHMENT',1.0],['MALWARE_DELIVERY',0.9],['TROJAN_DELIVERY',0.6]],
    'macro_enabled_document':     [['MALICIOUS_MACRO',1.0],['MALICIOUS_OFFICE_DOC',0.9],['MALWARE_DELIVERY',0.7]],
    'script_attachment':          [['MALICIOUS_SCRIPT',1.0],['MALWARE_DELIVERY',0.8]],
    'archive_attachment':         [['MALICIOUS_ARCHIVE',0.7],['SUSPICIOUS_ATTACHMENT',0.5]],
    'password_protected_archive': [['MALICIOUS_ARCHIVE',0.9],['HTML_SMUGGLING',0.4]],
    'html_attachment':            [['HTML_SMUGGLING',1.0],['MALWARE_DELIVERY',0.7]],
    'pdf_attachment':             [['MALICIOUS_PDF',0.6],['SUSPICIOUS_ATTACHMENT',0.4]],
    'suspicious_attachment':      [['SUSPICIOUS_ATTACHMENT',0.9]],
    // Header signals
    'header_anomaly':             [['SUSPICIOUS_HEADER',0.9],['DOMAIN_SPOOFING',0.4]],
    'route_anomaly':              [['SUSPICIOUS_HEADER',0.7]],
    'tracking_pixel':             [['RECONNAISSANCE',0.9]],
    'bulk_sender':                [['SPAM',0.7],['BULK_EMAIL',0.8]],
  },

  async analyze(emailData) {
    const timeline = [];
    const ts = () => new Date().toLocaleTimeString('en-GB', { hour12: false });

    timeline.push({ time: ts(), event: 'Email received for analysis' });

    // ─── Run all detectors ──────────────────────────────
    timeline.push({ time: ts(), event: 'Sender analysed' });
    const senderEvidence = SenderDetector.analyze(emailData);

    timeline.push({ time: ts(), event: 'Headers analysed' });
    const headerEvidence = HeaderDetector.analyze(emailData);

    timeline.push({ time: ts(), event: 'URLs extracted and analysed' });
    const urlEvidence = UrlDetector.analyze(emailData);

    timeline.push({ time: ts(), event: 'Content analysed' });
    const contentEvidence = ContentDetector.analyze(emailData);

    timeline.push({ time: ts(), event: 'Attachments analysed' });
    const attachmentEvidence = AttachmentDetector.analyze(emailData);

    // ─── Aggregate all evidence ─────────────────────────
    const allEvidence = [
      ...senderEvidence,
      ...headerEvidence,
      ...urlEvidence,
      ...contentEvidence,
      ...attachmentEvidence,
    ];

    timeline.push({ time: ts(), event: 'Evidence aggregated — ' + allEvidence.length + ' signals collected' });

    // ─── Score all categories ───────────────────────────
    const categoryScores = this._scoreCategoriesFromEvidence(allEvidence);
    timeline.push({ time: ts(), event: 'Threat categories scored' });

    // ─── Determine primary and secondary categories ─────
    const { primaryCategory, secondaryCategories } = this._selectCategories(categoryScores);
    timeline.push({ time: ts(), event: primaryCategory ? `Primary category identified: ${primaryCategory.id}` : 'No primary threat category identified' });

    // ─── Calculate risk score ───────────────────────────
    const riskResult = RiskCalculator.calculate(allEvidence);
    timeline.push({ time: ts(), event: `Risk calculated: ${riskResult.score}/100 — ${RiskCalculator.getSeverityLabel(riskResult.score).label}` });

    // ─── Generate explanation ───────────────────────────
    const explanation = ExplanationEngine.generate(
      primaryCategory, secondaryCategories, allEvidence, riskResult, null, emailData
    );
    timeline.push({ time: ts(), event: 'Explanation generated' });

    // ─── Determine recommended action ──────────────────
    const recommendedAction = this._determineAction(riskResult.score, primaryCategory);
    timeline.push({ time: ts(), event: `Policy evaluated — action: ${recommendedAction}` });

    if (recommendedAction === 'QUARANTINE') {
      timeline.push({ time: ts(), event: 'Email flagged for quarantine' });
    }

    // ─── Build normalised result object ────────────────
    const result = {
      is_threat: riskResult.score >= 25 && !!primaryCategory,
      primary_category: primaryCategory ? {
        id: primaryCategory.id,
        name: primaryCategory.name,
        confidence: riskResult.confidence,
        icon: primaryCategory.icon,
        parent: primaryCategory.parent,
        severity: primaryCategory.severity,
      } : null,
      secondary_categories: secondaryCategories.map(c => ({
        id: c.id,
        name: c.name,
        confidence: parseFloat((c.score / 100).toFixed(2)),
        icon: c.icon,
      })),
      risk_score: riskResult.score,
      severity: RiskCalculator.getSeverityLabel(riskResult.score),
      confidence_pct: Math.round(riskResult.confidence * 100),
      explanation,
      evidence: allEvidence.filter(e => !['sender_appears_normal','urls_appear_normal','content_appears_normal'].includes(e.signal)),
      evidence_grouped: ExplanationEngine.formatEvidenceList(allEvidence),
      recommended_action: recommendedAction,
      investigation_timeline: timeline,
      analysis_timestamp: new Date().toISOString(),
      email_subject: emailData.subject || 'Not available',
      email_from: emailData.from_email || 'Not available',
      email_from_name: emailData.from_name || 'Not available',
    };

    return result;
  },

  _scoreCategoriesFromEvidence(allEvidence) {
    const scores = {};

    for (const ev of allEvidence) {
      if (ExplanationEngine.isSafeSignal(ev.signal)) continue;

      const mappings = this.SIGNAL_CATEGORY_MAP[ev.signal] || [];
      const signalWeight = RiskCalculator.SIGNAL_WEIGHTS[ev.signal] || 5;

      for (const [catId, multiplier] of mappings) {
        const cat = THREAT_TAXONOMY.CATEGORIES[catId];
        if (!cat) continue;
        if (!scores[catId]) {
          scores[catId] = {
            id: catId,
            name: cat.category_name,
            icon: cat.icon,
            parent: THREAT_TAXONOMY.getParent(catId),
            severity: cat.severity,
            score: 0,
            signals: [],
          };
        }
        scores[catId].score += signalWeight * multiplier;
        scores[catId].signals.push(ev.signal);
      }
    }

    return scores;
  },

  _selectCategories(categoryScores) {
    const sorted = Object.values(categoryScores).sort((a, b) => b.score - a.score);

    if (sorted.length === 0) {
      return { primaryCategory: null, secondaryCategories: [] };
    }

    const primary = sorted[0];
    // Normalise scores relative to primary
    const maxScore = primary.score;
    const normalised = sorted.map(c => ({ ...c, score: Math.min(100, Math.round((c.score / maxScore) * 100)) }));

    const primaryCategory = normalised[0];
    // Secondary: score >= 40% of primary, up to 5 categories, distinct from primary
    const secondaryCategories = normalised
      .slice(1)
      .filter(c => c.score >= 40 && c.id !== primaryCategory.id)
      .slice(0, 5);

    return { primaryCategory, secondaryCategories };
  },

  _determineAction(riskScore, primaryCategory) {
    if (riskScore >= 70) return 'QUARANTINE';
    if (riskScore >= 50) return 'FLAG';
    if (riskScore >= 25) return 'WARN';
    return 'ALLOW';
  },

  getActionLabel(action) {
    const labels = {
      'QUARANTINE': { text: '🔒 QUARANTINED', color: '#FF2D55', description: 'Email quarantined — moved to security hold' },
      'FLAG':       { text: '🚩 FLAGGED',     color: '#FF6B35', description: 'Email flagged for review' },
      'WARN':       { text: '⚠️ WARNING',      color: '#FFD60A', description: 'Email marked as suspicious' },
      'ALLOW':      { text: '✅ ALLOWED',      color: '#34C759', description: 'Email allowed through' },
    };
    return labels[action] || labels['ALLOW'];
  },
};

if (typeof window !== 'undefined') window.AnalysisEngine = AnalysisEngine;
