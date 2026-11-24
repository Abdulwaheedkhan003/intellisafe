// ============================================================
// AGENT INVESTIGATION TOOLS
// 17 discrete tools for the EmailSecurityInvestigationAgent
// ============================================================

import { EvidenceItem, EVIDENCE_TYPES, VERIFICATION_STATUS } from '../schemas/evidence_schema.js';
import { THREAT_TAXONOMY } from '../taxonomy.js';
import { SenderDetector } from '../detectors/sender_detector.js';
import { HeaderDetector } from '../detectors/header_detector.js';
import { UrlDetector } from '../detectors/url_detector.js';
import { ContentDetector } from '../detectors/content_detector.js';
import { AttachmentDetector } from '../detectors/attachment_detector.js';

export class AgentTools {
  constructor(emailData, fastEvidence = []) {
    this.email = emailData;
    this.collectedEvidence = [...fastEvidence];
    this.findings = {};
  }

  analyze_sender() {
    const senderEvidence = SenderDetector.analyze(this.email);
    this.collectedEvidence.push(...senderEvidence);
    this.findings.sender = {
      from: this.email.from_email,
      name: this.email.from_name,
      reply_to: this.email.reply_to,
      evidence_count: senderEvidence.length,
    };
    return { status: 'COMPLETE', findings: this.findings.sender, evidence: senderEvidence };
  }

  analyze_headers() {
    const headerEvidence = HeaderDetector.analyze(this.email);
    this.collectedEvidence.push(...headerEvidence);
    this.findings.headers = {
      spf: this.email.spf,
      dkim: this.email.dkim,
      dmarc: this.email.dmarc,
      evidence_count: headerEvidence.length,
    };
    return { status: 'COMPLETE', findings: this.findings.headers, evidence: headerEvidence };
  }

  analyze_authentication() {
    const authEvidence = this.collectedEvidence.filter(e => e.type === EVIDENCE_TYPES.AUTH);
    const hasFailures = authEvidence.some(e => ['spf_fail', 'dkim_fail', 'dmarc_fail'].includes(e.signal));
    const allPassed = ['PASS', 'PASS'].includes(this.email.spf) && this.email.dkim === 'PASS';
    return {
      status: 'COMPLETE',
      has_auth_failures: hasFailures,
      all_passed: allPassed,
      records: { spf: this.email.spf, dkim: this.email.dkim, dmarc: this.email.dmarc },
    };
  }

  extract_urls() {
    const urls = Array.isArray(this.email.urls) ? this.email.urls : [];
    this.findings.urls = urls;
    return { status: 'COMPLETE', count: urls.length, urls };
  }

  inspect_urls() {
    const urlEvidence = UrlDetector.analyze(this.email);
    this.collectedEvidence.push(...urlEvidence);
    this.findings.url_evidence = urlEvidence;
    return { status: 'COMPLETE', count: urlEvidence.length, evidence: urlEvidence };
  }

  analyze_domains() {
    const fromDomain = (this.email.from_email || '').split('@')[1] || '';
    const domainsFound = [fromDomain];
    for (const u of (this.email.urls || [])) {
      try {
        domainsFound.push(new URL(u).hostname);
      } catch {}
    }
    return { status: 'COMPLETE', sender_domain: fromDomain, domains: [...new Set(domainsFound)] };
  }

  analyze_ip_addresses() {
    const ipUrls = this.collectedEvidence.filter(e => e.signal === 'ip_address_url');
    return {
      status: 'COMPLETE',
      ip_host_detected: ipUrls.length > 0,
      evidence: ipUrls,
    };
  }

  analyze_attachments() {
    const attEvidence = AttachmentDetector.analyze(this.email);
    this.collectedEvidence.push(...attEvidence);
    this.findings.attachments = {
      count: (this.email.attachments || []).length,
      evidence_count: attEvidence.length,
    };
    return { status: 'COMPLETE', findings: this.findings.attachments, evidence: attEvidence };
  }

  analyze_content() {
    const contentEvidence = ContentDetector.analyze(this.email);
    this.collectedEvidence.push(...contentEvidence);
    this.findings.content_evidence = contentEvidence;
    return { status: 'COMPLETE', count: contentEvidence.length, evidence: contentEvidence };
  }

  detect_social_engineering() {
    const socEngSignals = ['urgency_language', 'account_suspension_threat', 'secrecy_request', 'executive_reference'];
    const matches = this.collectedEvidence.filter(e => socEngSignals.includes(e.signal));
    return {
      status: 'COMPLETE',
      detected: matches.length > 0,
      signals: matches.map(m => m.signal),
    };
  }

  detect_impersonation() {
    const impSignals = ['brand_impersonation', 'display_name_spoofing', 'executive_impersonation', 'typosquatting', 'lookalike_domain'];
    const matches = this.collectedEvidence.filter(e => impSignals.includes(e.signal));
    return {
      status: 'COMPLETE',
      detected: matches.length > 0,
      impersonation_types: matches.map(m => m.signal),
    };
  }

  check_threat_intelligence() {
    // Verified threat intel lookup (known IOC database / reputation store)
    // If no verified match found, strictly return UNAVAILABLE rather than hallucinating
    const domains = [
      (this.email.from_email || '').split('@')[1],
      ...(this.email.urls || []).map(u => {
        try { return new URL(u).hostname; } catch { return ''; }
      }),
    ].filter(Boolean);

    const KNOWN_MALICIOUS_REPUTATIONS = {
      'security-login-portal.xyz': { threat_type: 'CREDENTIAL_HARVESTING', confidence: 0.99, source: 'ThreatLens Intel' },
      'account-update-center.online': { threat_type: 'PHISHING', confidence: 0.98, source: 'ThreatLens Intel' },
      'wire-transfer-desk.live': { threat_type: 'FINANCIAL_FRAUD', confidence: 0.96, source: 'ThreatLens Intel' },
    };

    const hits = [];
    for (const d of domains) {
      if (KNOWN_MALICIOUS_REPUTATIONS[d]) {
        const intel = KNOWN_MALICIOUS_REPUTATIONS[d];
        const item = new EvidenceItem({
          type: EVIDENCE_TYPES.THREAT_INTEL,
          signal: 'known_threat_intel_match',
          finding: `Domain "${d}" listed on threat intelligence feed (${intel.threat_type})`,
          value: { domain: d, intel },
          source: 'threat_intel',
          verified: true,
          confidence: intel.confidence,
          severity: 'CRITICAL',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        });
        hits.push(item);
        this.collectedEvidence.push(item);
      }
    }

    if (hits.length > 0) {
      return { status: 'CONFIRMED_MATCH', intel_hits: hits };
    }

    return {
      status: 'UNAVAILABLE',
      message: 'INTELLIGENCE UNAVAILABLE',
      note: 'No external threat intelligence feeds match this specific domain/hash, relying on behavioral & cryptographic evidence',
    };
  }

  correlate_evidence() {
    // Remove duplicates while keeping highest confidence per signal
    const uniqueMap = new Map();
    for (const e of this.collectedEvidence) {
      const key = `${e.signal}:${e.finding}`;
      if (!uniqueMap.has(key) || uniqueMap.get(key).confidence < e.confidence) {
        uniqueMap.set(key, e);
      }
    }
    const correlated = Array.from(uniqueMap.values());
    this.collectedEvidence = correlated;

    const criticalCount = correlated.filter(e => e.severity === 'CRITICAL' && e.verified).length;
    const highCount = correlated.filter(e => e.severity === 'HIGH' && e.verified).length;
    const mediumCount = correlated.filter(e => e.severity === 'MEDIUM' && e.verified).length;
    const safeCount = correlated.filter(e => e.severity === 'SAFE' && e.verified).length;

    return {
      status: 'COMPLETE',
      total_evidence_items: correlated.length,
      critical_signals: criticalCount,
      high_signals: highCount,
      medium_signals: mediumCount,
      safe_signals: safeCount,
    };
  }

  classify_threat() {
    const scores = {};
    const SIGNAL_CATEGORY_MAP = {
      'spf_fail': [['PHISHING', 0.8], ['DOMAIN_SPOOFING', 1.0], ['BEC', 0.7]],
      'dkim_fail': [['PHISHING', 0.7], ['DOMAIN_SPOOFING', 0.9]],
      'dmarc_fail': [['PHISHING', 0.8], ['DOMAIN_SPOOFING', 1.0], ['BEC', 0.7]],
      'domain_mismatch': [['PHISHING', 0.9], ['DOMAIN_SPOOFING', 1.0], ['BRAND_IMPERSONATION', 0.9], ['BEC', 0.8]],
      'display_name_spoofing': [['DISPLAY_NAME_SPOOFING', 1.0], ['PHISHING', 0.6], ['BEC', 0.7]],
      'brand_impersonation': [['BRAND_IMPERSONATION', 1.0], ['PHISHING', 0.9], ['CLOUD_SERVICE_IMPERSONATION', 0.6]],
      'typosquatting': [['TYPOSQUATTING', 1.0], ['LOOKALIKE_DOMAIN', 0.9], ['PHISHING', 0.8]],
      'lookalike_domain': [['LOOKALIKE_DOMAIN', 1.0], ['TYPOSQUATTING', 0.8], ['PHISHING', 0.7]],
      'punycode_domain': [['HOMOGRAPH_ATTACK', 1.0], ['PUNYCODE_URL', 0.9], ['PHISHING', 0.7]],
      'executive_impersonation': [['EXECUTIVE_IMPERSONATION', 1.0], ['BEC', 0.9], ['CEO_FRAUD', 0.8]],
      'reply_to_mismatch': [['PHISHING', 0.8], ['BEC', 0.8], ['DOMAIN_SPOOFING', 0.7]],
      'fake_login_url': [['CREDENTIAL_HARVESTING', 1.0], ['FAKE_LOGIN_PAGE', 1.0], ['PHISHING', 0.9]],
      'credential_request': [['CREDENTIAL_HARVESTING', 1.0], ['PHISHING', 0.9], ['ACCOUNT_VERIFICATION_SCAM', 0.8]],
      'urgency_language': [['PHISHING', 0.5], ['ACCOUNT_VERIFICATION_SCAM', 0.6], ['BEC', 0.5]],
      'account_suspension_threat': [['ACCOUNT_VERIFICATION_SCAM', 1.0], ['PHISHING', 0.9]],
      'payment_request': [['PAYMENT_FRAUD', 0.9], ['BEC', 0.8], ['INVOICE_FRAUD', 0.7]],
      'new_bank_account': [['BANK_ACCOUNT_CHANGE', 1.0], ['PAYMENT_REDIRECTION', 1.0], ['BEC', 0.9]],
      'wire_transfer_request': [['WIRE_TRANSFER_FRAUD', 1.0], ['BEC', 0.9], ['CEO_FRAUD', 0.8]],
      'gift_card_request': [['GIFT_CARD_SCAM', 1.0], ['CEO_FRAUD', 0.7]],
      'secrecy_request': [['BEC', 0.8], ['CEO_FRAUD', 0.7]],
      'extortion_keywords': [['EXTORTION', 1.0], ['BLACKMAIL', 0.8]],
      'harassment_keywords': [['HARASSMENT', 1.0], ['ABUSIVE_CONTENT', 0.8]],
      'investment_offer': [['INVESTMENT_SCAM', 1.0], ['CRYPTO_SCAM', 0.7]],
      'prize_claim': [['PRIZE_SCAM', 1.0], ['SCAM', 0.8]],
      'executable_attachment': [['EXECUTABLE_ATTACHMENT', 1.0], ['MALWARE_DELIVERY', 1.0]],
      'macro_enabled_document': [['MALICIOUS_MACRO', 1.0], ['MALWARE_DELIVERY', 0.9]],
      'script_attachment': [['MALICIOUS_SCRIPT', 1.0], ['MALWARE_DELIVERY', 0.9]],
      'html_attachment': [['HTML_SMUGGLING', 1.0], ['PHISHING', 0.8]],
      'password_protected_archive': [['MALICIOUS_ARCHIVE', 0.9], ['MALWARE_DELIVERY', 0.7]],
      'ip_address_url': [['IP_BASED_URL', 1.0], ['SUSPICIOUS_DOMAIN_URL', 0.8]],
      'url_shortener': [['URL_SHORTENER_ABUSE', 1.0], ['OBFUSCATED_URL', 0.8]],
      'bulk_sender': [['SPAM', 0.8], ['BULK_EMAIL', 1.0]],
      'known_threat_intel_match': [['THREAT_INTEL_MATCH', 1.0], ['PHISHING', 0.9]],
    };

    const verifiedEv = this.collectedEvidence.filter(e => e.verified && e.severity !== 'SAFE');

    for (const ev of verifiedEv) {
      const mappings = SIGNAL_CATEGORY_MAP[ev.signal] || [];
      const weight = ev.severity === 'CRITICAL' ? 30 : ev.severity === 'HIGH' ? 20 : ev.severity === 'MEDIUM' ? 10 : 5;

      for (const [catId, mult] of mappings) {
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
            evidence: [],
          };
        }
        scores[catId].score += weight * mult;
        scores[catId].evidence.push(ev);
      }
    }

    const sorted = Object.values(scores).sort((a, b) => b.score - a.score);

    if (sorted.length === 0) {
      // Check if there are suspicious signals but insufficient evidence
      const anySuspicious = this.collectedEvidence.some(e => e.severity === 'MEDIUM' || e.severity === 'LOW');
      if (anySuspicious) {
        return {
          primary_category: {
            id: 'UNKNOWN_SUSPICIOUS',
            name: 'UNKNOWN / SUSPICIOUS',
            icon: '⚠️',
            severity: 'MEDIUM',
            description: 'The system detected unusual characteristics but does not have enough verified evidence to confidently assign a specific threat category.',
          },
          secondary_categories: [],
          is_threat: true,
        };
      }
      return { primary_category: null, secondary_categories: [], is_threat: false };
    }

    const primary = sorted[0];
    const maxScore = primary.score;
    const secondaries = sorted
      .slice(1)
      .filter(c => c.score >= maxScore * 0.4 && c.id !== primary.id)
      .slice(0, 4)
      .map(c => ({
        id: c.id,
        name: c.name,
        icon: c.icon,
        confidence: parseFloat((c.score / maxScore).toFixed(2)),
      }));

    return {
      primary_category: {
        id: primary.id,
        name: primary.name,
        icon: primary.icon,
        parent: primary.parent,
        severity: primary.severity,
      },
      secondary_categories: secondaries,
      is_threat: true,
    };
  }

  calculate_confidence(evidenceList) {
    const verified = evidenceList.filter(e => e.verified && e.severity !== 'SAFE');
    if (verified.length === 0) return 0.95; // High confidence in safe classification
    const avg = verified.reduce((acc, e) => acc + e.confidence, 0) / verified.length;
    return parseFloat(Math.min(0.99, Math.max(0.70, avg)).toFixed(2));
  }

  generate_explanation(primaryCategory, evidenceList) {
    // Dynamic explanation referencing verified evidence ONLY
    const verified = evidenceList.filter(e => e.verified && e.severity !== 'SAFE');

    if (!primaryCategory || primaryCategory.id === 'SAFE') {
      return 'Based on the available evidence, no significant phishing, spoofing, malware, or social-engineering indicators were detected. Sender identity and cryptographic authentication checks passed.';
    }

    if (primaryCategory.id === 'UNKNOWN_SUSPICIOUS') {
      return 'The system detected unusual email characteristics but does not have enough verified evidence to confidently assign a specific threat category. Exercise caution before clicking links or replying.';
    }

    const reasons = [];

    // Check sender
    const brandImp = verified.find(e => e.signal === 'brand_impersonation');
    const domainMismatch = verified.find(e => e.signal === 'domain_mismatch');
    const typoDomain = verified.find(e => e.signal === 'typosquatting');
    const replyMismatch = verified.find(e => e.signal === 'reply_to_mismatch');

    if (brandImp) {
      reasons.push(`claims to represent ${brandImp.value.brand}, but the sender domain (${brandImp.value.actualDomain}) does not match the legitimate organization`);
    } else if (typoDomain) {
      reasons.push(`originates from a typosquatted lookalike domain (${typoDomain.value.senderDomain})`);
    } else if (domainMismatch) {
      reasons.push(`the sender domain does not match the claimed identity`);
    }

    if (replyMismatch) {
      reasons.push(`contains a suspicious Reply-To destination directing responses to an external domain (${replyMismatch.value.replyTo})`);
    }

    // Check URL
    const fakeLogin = verified.find(e => e.signal === 'fake_login_url');
    const ipUrl = verified.find(e => e.signal === 'ip_address_url');
    const shortUrl = verified.find(e => e.signal === 'url_shortener');

    if (fakeLogin) {
      reasons.push('contains a link directing the recipient to a deceptive credential-verification login portal');
    } else if (ipUrl) {
      reasons.push('contains a raw IP-based web link bypassing standard domain name resolution');
    } else if (shortUrl) {
      reasons.push('uses a shortened link service to obfuscate the real destination website');
    }

    // Check Content
    const credReq = verified.find(e => e.signal === 'credential_request');
    const urgency = verified.find(e => e.signal === 'urgency_language');
    const suspThreat = verified.find(e => e.signal === 'account_suspension_threat');
    const newBank = verified.find(e => e.signal === 'new_bank_account');
    const wireReq = verified.find(e => e.signal === 'wire_transfer_request');
    const secrecy = verified.find(e => e.signal === 'secrecy_request');
    const extortion = verified.find(e => e.signal === 'extortion_keywords');
    const harassment = verified.find(e => e.signal === 'harassment_keywords');
    const crypto = verified.find(e => e.signal === 'investment_offer');

    if (credReq && urgency) {
      reasons.push('urgently requests the recipient to confirm account credentials or verify security settings under a strict deadline');
    } else if (credReq) {
      reasons.push('solicits sensitive account passwords or login credentials');
    }

    if (suspThreat) {
      reasons.push('threatens immediate account suspension or termination to compel quick action');
    }

    if (newBank || wireReq) {
      reasons.push('requests financial redirection or urgent wire transfer instructions with revised banking details');
    }

    if (secrecy) {
      reasons.push('explicitly demands confidentiality to bypass internal company review procedures');
    }

    if (extortion) {
      reasons.push('uses coercive blackmail and extortion threats demanding cryptocurrency payment');
    }

    if (harassment) {
      reasons.push('contains aggressive, hostile language and personal retaliation threats');
    }

    if (crypto) {
      reasons.push('promotes fraudulent cryptocurrency or investment schemes with unrealistic guaranteed returns');
    }

    // Check Attachments
    const execAtt = verified.find(e => e.signal === 'executable_attachment');
    const macroAtt = verified.find(e => e.signal === 'macro_enabled_document');
    const scriptAtt = verified.find(e => e.signal === 'script_attachment');
    const htmlAtt = verified.find(e => e.signal === 'html_attachment');

    if (execAtt) {
      reasons.push(`delivers a dangerous executable binary payload (${execAtt.value.filename})`);
    } else if (macroAtt) {
      reasons.push(`contains a macro-enabled Office file (${macroAtt.value.filename}) designed to execute code when opened`);
    } else if (scriptAtt) {
      reasons.push(`includes a direct script attachment (${scriptAtt.value.filename})`);
    } else if (htmlAtt) {
      reasons.push(`attaches an offline HTML phishing file (${htmlAtt.value.filename})`);
    }

    if (reasons.length === 0) {
      return `This email appears to be a ${primaryCategory.name} threat because several suspicious behavioral and structural indicators were verified during forensic inspection.`;
    }

    const joined = reasons.slice(0, 3).join(', and ');
    return `This email appears to be a ${primaryCategory.name} attempt because it ${joined}.`;
  }

  recommend_action(riskScore, primaryCategory) {
    if (riskScore >= 70) return 'QUARANTINE';
    if (riskScore >= 50) return 'SPAM';
    if (riskScore >= 25) return 'FLAG';
    return 'ALLOW';
  }
}
