// ============================================================
// RISK CALCULATOR
// Converts collected evidence into a weighted 0-100 risk score.
// Score reflects the combined severity of all detected signals.
// ============================================================

const RiskCalculator = {

  // Signal-level weights (0-100)
  SIGNAL_WEIGHTS: {
    // Critical/Very High (70-100)
    'ransomware_payload':         100,
    'executable_attachment':       95,
    'rat_payload':                 95,
    'wire_transfer_request':       92,
    'extortion_keywords':          92,
    'blackmail_keywords':          91,
    'new_bank_account':            90,
    'payroll_change_request':      90,
    'fake_login_url':              88,
    'credential_harvesting':       88,
    'credential_request':          85,
    'html_attachment':             82,
    'macro_enabled_document':      80,
    'spf_fail':                    78,
    'dkim_fail':                   78,
    'dmarc_fail':                  80,
    'payment_request':             75,
    'financial_request':           72,
    'executive_impersonation':     70,
    'brand_impersonation':         70,
    'domain_mismatch':             68,

    // High (40-69)
    'script_attachment':           65,
    'obfuscated_url':              63,
    'ip_address_url':              62,
    'display_name_spoofing':       60,
    'urgency_language':            55,
    'gift_card_request':           60,
    'secrecy_request':             65,
    'account_suspension_threat':   58,
    'threat_language':             60,
    'threat_language_high':        68,
    'punycode_domain':             62,
    'typosquatting':               60,
    'lookalike_domain':            60,
    'sensitive_info_request':      58,
    'password_protected_archive':  58,
    'archive_attachment':          40,
    'crypto_payment_request':      65,
    'tax_authority_impersonation': 62,
    'government_agency_keyword':   50,
    'extortion':                   90,
    'bank_keyword':                45,
    'header_anomaly':              50,
    'route_anomaly':               35,

    // Medium (15-39)
    'spf_softfail':                30,
    'spf_none':                    20,
    'dkim_none':                   15,
    'dmarc_none':                  15,
    'url_shortener':               30,
    'suspicious_link':             35,
    'suspicious_domain':           35,
    'unusual_sender':              28,
    'executive_reference':         38,
    'prize_claim':                 30,
    'lottery_win_claim':           30,
    'investment_offer':            35,
    'unrealistic_returns':         35,
    'scam_keywords':               32,
    'scare_tactic':                30,
    'office_attachment':           20,
    'pdf_attachment':              15,
    'tracking_pixel':              15,
    'open_rate_tracking':          10,
    'harassment_keywords':         35,
    'abusive_language':            30,

    // Low / Neutral
    'bulk_sender':                 10,
    'unexpected_attachment':       10,
    'suspicious_attachment':       25,
    'cloud_service_keyword':       20,
    'double_extension':            45,
    'unknown_signal':              5,
  },

  calculate(allEvidence) {
    const positiveEvidence = allEvidence.filter(e =>
      !['sender_appears_normal', 'urls_appear_normal', 'content_appears_normal',
        'spf_pass', 'dkim_pass', 'dmarc_pass'].includes(e.signal)
    );

    if (positiveEvidence.length === 0) {
      return { score: 5, confidence: 0.95, basis: 'no_threats_detected' };
    }

    // Collect unique signals and their highest-weighted score
    const signalMap = new Map();
    for (const ev of positiveEvidence) {
      const weight = this.SIGNAL_WEIGHTS[ev.signal] || this.SIGNAL_WEIGHTS.unknown_signal;
      if (!signalMap.has(ev.signal) || signalMap.get(ev.signal) < weight) {
        signalMap.set(ev.signal, weight);
      }
    }

    const weights = Array.from(signalMap.values()).sort((a, b) => b - a);

    if (weights.length === 0) return { score: 5, confidence: 0.5, basis: 'no_scored_signals' };

    // Primary: highest single signal drives the base
    const primary = weights[0];
    let score = primary;

    // Secondary signals add diminishing contributions
    for (let i = 1; i < weights.length; i++) {
      const contribution = weights[i] * Math.pow(0.35, i);
      score = Math.min(100, score + contribution);
    }

    score = Math.round(score);

    // Confidence based on number and consistency of signals
    const signalCount = weights.length;
    const topSignalsAgree = weights.filter(w => w >= 60).length;
    let confidence = Math.min(0.99, 0.5 + (signalCount * 0.08) + (topSignalsAgree * 0.06));

    // Auth failures boost confidence
    const authFailures = positiveEvidence.filter(e => ['spf_fail', 'dkim_fail', 'dmarc_fail'].includes(e.signal)).length;
    confidence = Math.min(0.99, confidence + authFailures * 0.05);

    return {
      score: Math.max(1, Math.min(100, score)),
      confidence: parseFloat(confidence.toFixed(2)),
      signal_count: signalCount,
      basis: 'weighted_evidence',
    };
  },

  getSeverityLabel(score) {
    if (score >= 80) return { label: 'CRITICAL', color: '#FF2D55', textColor: '#fff' };
    if (score >= 60) return { label: 'HIGH',     color: '#FF6B35', textColor: '#fff' };
    if (score >= 35) return { label: 'MEDIUM',   color: '#FFD60A', textColor: '#000' };
    if (score >= 10) return { label: 'LOW',      color: '#34C759', textColor: '#fff' };
    return              { label: 'INFO',      color: '#636366', textColor: '#fff' };
  },
};

if (typeof window !== 'undefined') window.RiskCalculator = RiskCalculator;
