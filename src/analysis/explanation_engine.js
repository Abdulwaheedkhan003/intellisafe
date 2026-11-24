// ============================================================
// EXPLANATION ENGINE
// Generates dynamic, evidence-based human-readable explanations.
//
// STRICT NO-FABRICATION: Only uses signals actually present in
// the evidence collection. Never invents domains, URLs, senders,
// threats, or organisations.
// ============================================================

const ExplanationEngine = {

  // Maps evidence signals to human-readable label phrases
  SIGNAL_LABELS: {
    'spf_fail':                   'SPF authentication failed',
    'spf_softfail':               'SPF authentication softfail',
    'spf_none':                   'No SPF record published',
    'dkim_fail':                  'DKIM signature invalid',
    'dkim_none':                  'No DKIM signature',
    'dmarc_fail':                 'DMARC policy check failed',
    'dmarc_none':                 'No DMARC policy',
    'spf_pass':                   'SPF check passed',
    'dkim_pass':                  'DKIM signature valid',
    'dmarc_pass':                 'DMARC check passed',
    'domain_mismatch':            'Sender domain mismatch',
    'display_name_spoofing':      'Display name spoofing',
    'brand_impersonation':        'Brand impersonation detected',
    'typosquatting':              'Typosquatted domain',
    'lookalike_domain':           'Lookalike domain',
    'punycode_domain':            'Punycode/homograph domain',
    'executive_impersonation':    'Executive impersonation',
    'unusual_sender':             'Unusual sender (free email provider)',
    'fake_login_url':             'Fake login page URL',
    'credential_request':         'Credential/login request',
    'credential_harvesting':      'Credential harvesting',
    'obfuscated_url':             'Obfuscated/hidden URL',
    'ip_address_url':             'IP-based URL (no domain)',
    'url_shortener':              'URL shortener used',
    'suspicious_link':            'Suspicious link',
    'suspicious_domain':          'Suspicious domain',
    'urgency_language':           'Urgency language',
    'account_suspension_threat':  'Account suspension threat',
    'payment_request':            'Payment request',
    'financial_request':          'Unusual financial request',
    'new_bank_account':           'New bank account details',
    'wire_transfer_request':      'Wire transfer request',
    'gift_card_request':          'Gift card purchase request',
    'secrecy_request':            'Secrecy/confidentiality request',
    'executive_reference':        'Executive authority claim',
    'extortion_keywords':         'Extortion language',
    'blackmail_keywords':         'Blackmail language',
    'threat_language':            'Threatening language',
    'harassment_keywords':        'Harassment content',
    'prize_claim':                'Fraudulent prize claim',
    'lottery_win_claim':          'Lottery scam claim',
    'investment_offer':           'Fraudulent investment offer',
    'unrealistic_returns':        'Unrealistic financial returns',
    'crypto_payment_request':     'Cryptocurrency payment demand',
    'tax_authority_impersonation':'Tax authority impersonation',
    'government_agency_keyword':  'Government agency reference',
    'executable_attachment':      'Executable file attached',
    'macro_enabled_document':     'Macro-enabled document attached',
    'office_attachment':          'Office document attached',
    'script_attachment':          'Script file attached',
    'archive_attachment':         'Archive file attached',
    'password_protected_archive': 'Password-protected archive',
    'pdf_attachment':             'PDF attachment',
    'html_attachment':            'HTML attachment (smuggling risk)',
    'suspicious_attachment':      'Suspicious attachment',
    'unexpected_attachment':      'Unexpected attachment',
    'bank_keyword':               'Banking/financial reference',
    'cloud_service_keyword':      'Cloud service reference',
    'sensitive_info_request':     'Sensitive information requested',
    'payroll_change_request':     'Payroll account change request',
    'scam_keywords':              'Known scam language',
    'scare_tactic':               'Scare tactic / false alarm',
    'tracking_pixel':             'Tracking pixel (reconnaissance)',
    'header_anomaly':             'Email header anomaly',
    'route_anomaly':              'Unusual routing',
    'bulk_sender':                'Bulk/mass-mailing software',
  },

  SAFE_SIGNALS: [
    'sender_appears_normal', 'urls_appear_normal', 'content_appears_normal',
    'spf_pass', 'dkim_pass', 'dmarc_pass',
  ],

  generate(primaryCategory, secondaryCategories, allEvidence, riskResult, recommendedAction, emailData) {
    const positiveEvidence = allEvidence.filter(e =>
      !this.SAFE_SIGNALS.includes(e.signal) &&
      !['LOW', 'NONE', 'INFO'].includes(e.severity) || // include if medium+
      ['tracking_pixel', 'spf_none', 'dkim_none', 'dmarc_none', 'bulk_sender'].includes(e.signal)
    ).filter(e => !this.SAFE_SIGNALS.includes(e.signal));

    if (!primaryCategory) {
      return this._generateSafeExplanation(allEvidence);
    }

    const catDef = THREAT_TAXONOMY.CATEGORIES[primaryCategory.id];
    if (!catDef) return 'Analysis complete. See evidence below.';

    // Build explanation from actual evidence
    const evidencePhrases = this._buildEvidencePhrases(positiveEvidence, emailData);
    const explanation = this._buildExplanationText(catDef, evidencePhrases, riskResult, emailData);

    return explanation;
  },

  generateSafe(allEvidence) {
    return this._generateSafeExplanation(allEvidence);
  },

  _generateSafeExplanation(allEvidence) {
    const passing = allEvidence.filter(e => this.SAFE_SIGNALS.includes(e.signal));
    const parts = [];

    parts.push('No significant phishing, spoofing, malware, or social-engineering indicators were detected in this email.');

    if (passing.length > 0) {
      parts.push('Authentication checks confirm the email\'s legitimacy:');
    }

    return parts.join(' ');
  },

  _buildEvidencePhrases(evidence, emailData) {
    if (evidence.length === 0) return [];

    // Group evidence by type and build readable sentences
    const phrases = [];
    const seen = new Set();

    // Prioritise the most impactful evidence signals for explanation
    const priority = [
      'brand_impersonation', 'domain_mismatch', 'display_name_spoofing',
      'fake_login_url', 'credential_request', 'new_bank_account', 'wire_transfer_request',
      'executive_impersonation', 'urgency_language', 'account_suspension_threat',
      'extortion_keywords', 'blackmail_keywords', 'executable_attachment',
      'macro_enabled_document', 'secrecy_request', 'payroll_change_request',
      'spf_fail', 'dkim_fail', 'dmarc_fail',
    ];

    // Add priority evidence first
    for (const signal of priority) {
      const ev = evidence.find(e => e.signal === signal && !seen.has(e.signal));
      if (ev) {
        seen.add(ev.signal);
        if (ev.finding && ev.finding.length > 20) {
          phrases.push(ev.finding.charAt(0).toUpperCase() + ev.finding.slice(1));
        }
      }
      if (phrases.length >= 4) break;
    }

    // Fill in remaining signals if under 3 phrases
    if (phrases.length < 3) {
      for (const ev of evidence) {
        if (!seen.has(ev.signal) && ev.finding && ev.finding.length > 20) {
          seen.add(ev.signal);
          phrases.push(ev.finding.charAt(0).toUpperCase() + ev.finding.slice(1));
          if (phrases.length >= 4) break;
        }
      }
    }

    return phrases;
  },

  _buildExplanationText(catDef, evidencePhrases, riskResult, emailData) {
    const catName = catDef.category_name;
    const severity = riskResult && riskResult.score >= 80 ? 'critical' :
                     riskResult && riskResult.score >= 60 ? 'significant' : 'notable';

    if (evidencePhrases.length === 0) {
      // Fallback if no evidence phrases built (shouldn't happen in practice)
      return `This email has been classified as a ${catName} threat based on patterns consistent with this attack type. Insufficient specific evidence was captured to generate a detailed explanation — review the evidence section for available signals.`;
    }

    // Compose a coherent paragraph from evidence phrases
    let text = `This email has been classified as ${catName} because `;

    if (evidencePhrases.length === 1) {
      // Single key finding
      text += evidencePhrases[0].replace(/^[A-Z]/, c => c.toLowerCase()) + '.';
    } else if (evidencePhrases.length === 2) {
      const p1 = evidencePhrases[0].replace(/\.$/, '').replace(/^[A-Z]/, c => c.toLowerCase());
      const p2 = evidencePhrases[1].replace(/\.$/, '').replace(/^[A-Z]/, c => c.toLowerCase());
      text += `${p1}, and ${p2}.`;
    } else {
      // Multiple findings — build compound sentence
      const parts = evidencePhrases.map(p => p.replace(/\.$/, '').replace(/^[A-Z]/, c => c.toLowerCase()));
      const last = parts.pop();
      text += parts.join('; ') + '; and ' + last + '.';
    }

    // Add severity context
    if (riskResult && riskResult.score >= 60) {
      text += ` These indicators collectively represent a ${severity} threat that warrants immediate attention.`;
    }

    return text;
  },

  formatEvidenceList(allEvidence) {
    const groups = {
      'Authentication': [],
      'Sender': [],
      'URLs': [],
      'Content': [],
      'Attachments': [],
      'Headers': [],
      'Other': [],
    };

    const authSignals = ['spf_fail','spf_softfail','spf_none','dkim_fail','dkim_none','dmarc_fail','dmarc_none','spf_pass','dkim_pass','dmarc_pass'];
    const senderSignals = ['domain_mismatch','display_name_spoofing','brand_impersonation','typosquatting','lookalike_domain','punycode_domain','executive_impersonation','unusual_sender'];
    const urlSignals = ['fake_login_url','obfuscated_url','ip_address_url','url_shortener','suspicious_link','suspicious_domain','credential_request'];
    const contentSignals = ['urgency_language','account_suspension_threat','payment_request','financial_request','new_bank_account','wire_transfer_request','gift_card_request','secrecy_request','executive_reference','extortion_keywords','blackmail_keywords','threat_language','prize_claim','scam_keywords','payroll_change_request','scare_tactic','bank_keyword','crypto_payment_request','sensitive_info_request'];
    const attachmentSignals = ['executable_attachment','macro_enabled_document','office_attachment','script_attachment','archive_attachment','password_protected_archive','pdf_attachment','html_attachment','suspicious_attachment','unexpected_attachment'];
    const headerSignals = ['header_anomaly','route_anomaly','bulk_sender','tracking_pixel'];

    for (const ev of allEvidence) {
      if (authSignals.includes(ev.signal)) groups['Authentication'].push(ev);
      else if (senderSignals.includes(ev.signal)) groups['Sender'].push(ev);
      else if (urlSignals.includes(ev.signal)) groups['URLs'].push(ev);
      else if (contentSignals.includes(ev.signal)) groups['Content'].push(ev);
      else if (attachmentSignals.includes(ev.signal)) groups['Attachments'].push(ev);
      else if (headerSignals.includes(ev.signal)) groups['Headers'].push(ev);
      else groups['Other'].push(ev);
    }

    return groups;
  },

  getSignalLabel(signal) {
    return this.SIGNAL_LABELS[signal] || signal.replace(/_/g, ' ');
  },

  isSafeSignal(signal) {
    return this.SAFE_SIGNALS.includes(signal);
  },

  getSeverityIcon(severity) {
    const icons = { 'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'NONE': '✓', 'INFO': 'ℹ️' };
    return icons[severity] || '⚠️';
  },
};

if (typeof window !== 'undefined') window.ExplanationEngine = ExplanationEngine;
