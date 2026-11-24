// ============================================================
// SENDER DETECTOR — Backend Module
// Analyses sender identity, display name, domain spoofing,
// typosquatting, lookalike domains, and brand impersonation.
// ============================================================

import { EvidenceItem, EVIDENCE_TYPES, VERIFICATION_STATUS } from '../schemas/evidence_schema.js';

export class SenderDetector {
  static BRAND_DOMAINS = {
    'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com', 'microsoft365.com', 'azure.com'],
    'google': ['google.com', 'gmail.com', 'googlemail.com', 'workspace.google.com'],
    'apple': ['apple.com', 'icloud.com', 'me.com'],
    'amazon': ['amazon.com', 'aws.amazon.com', 'amazon.co.uk', 'amazon.in'],
    'paypal': ['paypal.com', 'paypal.co.uk'],
    'facebook': ['facebook.com', 'facebookmail.com', 'fb.com', 'meta.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com', 'e.linkedin.com'],
    'dropbox': ['dropbox.com'],
    'docusign': ['docusign.com', 'docusign.net'],
    'chase': ['chase.com', 'jpmorgan.com'],
    'bank of america': ['bankofamerica.com'],
    'wells fargo': ['wellsfargo.com'],
    'netflix': ['netflix.com'],
    'adobe': ['adobe.com'],
    'zoom': ['zoom.us', 'zoom.com'],
    'slack': ['slack.com'],
    'salesforce': ['salesforce.com'],
    'irs': ['irs.gov'],
    'fbi': ['fbi.gov'],
    'dhs': ['dhs.gov'],
    'usps': ['usps.com', 'usps.gov'],
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'dhl': ['dhl.com'],
  };

  static FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'protonmail.com', 'mail.com', 'icloud.com', 'zoho.com',
    'yandex.com', 'gmx.com', 'tutanota.com', 'fastmail.com',
  ];

  static EXECUTIVE_KEYWORDS = [
    'ceo', 'cfo', 'coo', 'ciso', 'president', 'director', 'vp of',
    'vice president', 'chief executive', 'chief financial', 'chief operating',
    'managing director', 'head of', 'executive director', 'partner',
  ];

  static TYPO_SUBSTITUTIONS = [
    ['rn', 'm'], ['l', '1'], ['o', '0'], ['vv', 'w'],
    ['cl', 'd'], ['i', 'l'], ['e', '3'],
  ];

  static analyze(emailData) {
    const evidence = [];
    const senderEmail = (emailData.from_email || '').toLowerCase().trim();
    const displayName = (emailData.from_name || '').toLowerCase().trim();
    const senderDomain = this._extractDomain(senderEmail);

    if (!senderEmail) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'missing_sender',
        finding: 'Sender address is missing or could not be extracted',
        value: null,
        source: 'sender_detector',
        verified: true,
        confidence: 0.95,
        severity: 'HIGH',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
      return evidence;
    }

    // 1. Display name vs actual domain mismatch
    const nameEmailMismatch = this._checkDisplayNameMismatch(displayName, senderDomain);
    if (nameEmailMismatch) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'display_name_spoofing',
        finding: `Display name "${emailData.from_name}" does not match actual sender domain "${senderDomain}"`,
        value: { displayName: emailData.from_name, senderDomain },
        source: 'sender_detector',
        verified: true,
        confidence: 0.92,
        severity: 'HIGH',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    // 2. Brand impersonation check
    const brandCheck = this._checkBrandImpersonation(displayName, senderDomain);
    if (brandCheck) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'brand_impersonation',
        finding: `Email claims to represent "${brandCheck.claimedBrand}" but originates from "${senderDomain}" instead of canonical domain (${brandCheck.expectedDomains.join(', ')})`,
        value: { brand: brandCheck.claimedBrand, actualDomain: senderDomain, expectedDomains: brandCheck.expectedDomains },
        source: 'sender_detector',
        verified: true,
        confidence: 0.97,
        severity: 'CRITICAL',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'domain_mismatch',
        finding: `Sender domain "${senderDomain}" does not match the claimed organization "${brandCheck.claimedBrand}"`,
        value: senderDomain,
        source: 'sender_detector',
        verified: true,
        confidence: 0.95,
        severity: 'CRITICAL',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    // 3. Typosquatted domain
    const typoCheck = this._checkTyposquatting(senderDomain);
    if (typoCheck) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'typosquatting',
        finding: `Sender domain "${senderDomain}" appears to be a typosquatted lookalike of "${typoCheck.targetDomain}"`,
        value: { senderDomain, targetDomain: typoCheck.targetDomain },
        source: 'sender_detector',
        verified: true,
        confidence: 0.93,
        severity: 'CRITICAL',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'lookalike_domain',
        finding: `Domain "${senderDomain}" closely mimics "${typoCheck.targetDomain}"`,
        value: senderDomain,
        source: 'sender_detector',
        verified: true,
        confidence: 0.90,
        severity: 'HIGH',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    // 4. Punycode/homograph check
    if (senderDomain.startsWith('xn--') || /[^\x00-\x7F]/.test(senderDomain)) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'punycode_domain',
        finding: `Sender domain "${senderDomain}" uses Punycode/internationalised characters (potential homograph attack)`,
        value: senderDomain,
        source: 'sender_detector',
        verified: true,
        confidence: 0.96,
        severity: 'CRITICAL',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    // 5. Executive impersonation via display name
    const execCheck = this._checkExecutiveImpersonation(displayName, senderDomain);
    if (execCheck) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'executive_impersonation',
        finding: `Display name includes executive title "${execCheck.title}" sent from non-corporate/free provider "${senderDomain}"`,
        value: { title: execCheck.title, senderDomain },
        source: 'sender_detector',
        verified: true,
        confidence: 0.88,
        severity: 'HIGH',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    // 6. Reply-To mismatch
    if (emailData.reply_to) {
      const replyToEmail = (emailData.reply_to || '').toLowerCase().trim();
      const replyToDomain = this._extractDomain(replyToEmail);
      if (replyToDomain && replyToDomain !== senderDomain) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.SENDER,
          signal: 'reply_to_mismatch',
          finding: `Reply-To header points to "${replyToEmail}" (${replyToDomain}), which does not match sender domain "${senderDomain}"`,
          value: { replyTo: replyToEmail, fromDomain: senderDomain },
          source: 'sender_detector',
          verified: true,
          confidence: 0.91,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    // 7. Safe sender verification
    if (evidence.length === 0) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.SENDER,
        signal: 'sender_appears_normal',
        finding: `Sender identity "${emailData.from_email || emailData.from_raw}" matches domain and shows no spoofing indicators`,
        value: senderEmail,
        source: 'sender_detector',
        verified: true,
        confidence: 0.90,
        severity: 'SAFE',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    return evidence;
  }

  static _extractDomain(email) {
    if (!email) return '';
    const parts = email.split('@');
    return parts.length > 1 ? parts[1].toLowerCase().trim() : '';
  }

  static _checkDisplayNameMismatch(displayName, senderDomain) {
    if (!displayName || !senderDomain) return false;
    for (const [brand, domains] of Object.entries(this.BRAND_DOMAINS)) {
      if (displayName.includes(brand) && !domains.includes(senderDomain)) {
        return true;
      }
    }
    return false;
  }

  static _checkBrandImpersonation(displayName, senderDomain) {
    if (!displayName) return null;
    for (const [brand, domains] of Object.entries(this.BRAND_DOMAINS)) {
      if (displayName.includes(brand)) {
        const isLegit = domains.some(d => senderDomain === d || senderDomain.endsWith('.' + d));
        if (!isLegit) {
          return {
            claimedBrand: brand.charAt(0).toUpperCase() + brand.slice(1),
            expectedDomains: domains,
          };
        }
      }
    }
    return null;
  }

  static _checkTyposquatting(senderDomain) {
    if (!senderDomain) return null;
    const base = senderDomain.split('.')[0];
    const parts = [base, ...base.split('-')];

    for (const part of parts) {
      if (!part) continue;
      for (const [brand, domains] of Object.entries(this.BRAND_DOMAINS)) {
        const canonicalBase = domains[0].split('.')[0];
        if (part === canonicalBase) continue;
        if (this._isLevenshteinClose(part, canonicalBase, 2)) {
          return { targetDomain: domains[0] };
        }
        for (const [sub, orig] of this.TYPO_SUBSTITUTIONS) {
          if (part.split(sub).join(orig) === canonicalBase) {
            return { targetDomain: domains[0] };
          }
        }
      }
    }
    return null;
  }

  static _isLevenshteinClose(a, b, maxDistance) {
    if (Math.abs(a.length - b.length) > maxDistance) return false;
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
    return dp[m][n] <= maxDistance && dp[m][n] > 0;
  }

  static _checkExecutiveImpersonation(displayName, senderDomain) {
    if (!displayName) return null;
    const isFreeProvider = this.FREE_EMAIL_PROVIDERS.includes(senderDomain);
    if (!isFreeProvider) return null;
    for (const kw of this.EXECUTIVE_KEYWORDS) {
      if (displayName.includes(kw)) {
        return { title: kw.toUpperCase() };
      }
    }
    return null;
  }
}
