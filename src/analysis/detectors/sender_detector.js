// ============================================================
// SENDER DETECTOR
// Analyses the sender address, display name, and domain for
// spoofing, impersonation, and anomaly signals.
// ============================================================

const SenderDetector = {

  // Known brand domains mapped to their canonical domains
  BRAND_DOMAINS: {
    'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com', 'microsoft365.com'],
    'google': ['google.com', 'gmail.com', 'googlemail.com', 'workspace.google.com'],
    'apple': ['apple.com', 'icloud.com', 'me.com'],
    'amazon': ['amazon.com', 'aws.amazon.com', 'amazon.co.uk', 'amazon.in'],
    'paypal': ['paypal.com', 'paypal.co.uk'],
    'facebook': ['facebook.com', 'facebookmail.com', 'fb.com'],
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
  },

  // Common free/public email providers (not inherently malicious but suspicious for business contexts)
  FREE_EMAIL_PROVIDERS: [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'protonmail.com', 'mail.com', 'icloud.com', 'zoho.com',
    'yandex.com', 'gmx.com', 'tutanota.com', 'fastmail.com',
  ],

  // Executive role keywords that might appear in display names
  EXECUTIVE_KEYWORDS: [
    'ceo', 'cfo', 'coo', 'ciso', 'president', 'director', 'vp of',
    'vice president', 'chief executive', 'chief financial', 'chief operating',
    'managing director', 'head of', 'executive director', 'partner',
  ],

  // Common typosquatting patterns (character substitutions)
  TYPO_SUBSTITUTIONS: [
    ['rn', 'm'], ['l', '1'], ['o', '0'], ['vv', 'w'],
    ['cl', 'd'], ['i', 'l'], ['e', '3'],
  ],

  analyze(emailData) {
    const evidence = [];
    const senderEmail = (emailData.from_email || '').toLowerCase().trim();
    const displayName = (emailData.from_name || '').toLowerCase().trim();
    const senderDomain = this._extractDomain(senderEmail);
    const claimedOrg = emailData.claimed_organization || '';

    if (!senderEmail) {
      evidence.push({ signal: 'missing_sender', finding: 'Sender address is missing or could not be extracted', verified: true, severity: 'HIGH' });
      return evidence;
    }

    // ─ 1. Display name vs actual domain mismatch ────────
    const nameEmailMismatch = this._checkDisplayNameMismatch(displayName, senderDomain);
    if (nameEmailMismatch) {
      evidence.push({
        signal: 'display_name_spoofing',
        finding: `Display name "${emailData.from_name}" does not match the actual sender domain "${senderDomain}"`,
        verified: true,
        severity: 'HIGH',
      });
    }

    // ─ 2. Brand impersonation check ─────────────────────
    const brandCheck = this._checkBrandImpersonation(displayName, senderDomain);
    if (brandCheck) {
      evidence.push({
        signal: 'brand_impersonation',
        finding: `Email claims to be from "${brandCheck.claimedBrand}" but originates from "${senderDomain}" instead of "${brandCheck.expectedDomains.join(' or ')}"`,
        verified: true,
        severity: 'CRITICAL',
      });
      evidence.push({
        signal: 'domain_mismatch',
        finding: `Sender domain "${senderDomain}" does not match the claimed organisation "${brandCheck.claimedBrand}"`,
        verified: true,
        severity: 'CRITICAL',
      });
    }

    // ─ 3. Lookalike / typosquatted domain ───────────────
    const typoCheck = this._checkTyposquatting(senderDomain);
    if (typoCheck) {
      evidence.push({
        signal: 'typosquatting',
        finding: `Sender domain "${senderDomain}" appears to be a typosquatted version of "${typoCheck.targetDomain}"`,
        verified: true,
        severity: 'HIGH',
      });
      evidence.push({
        signal: 'lookalike_domain',
        finding: `Domain "${senderDomain}" is visually similar to legitimate domain "${typoCheck.targetDomain}"`,
        verified: true,
        severity: 'HIGH',
      });
    }

    // ─ 4. Punycode / homograph detection ────────────────
    if (senderDomain.startsWith('xn--') || /xn--/i.test(senderDomain)) {
      evidence.push({
        signal: 'punycode_domain',
        finding: `Sender domain "${senderDomain}" uses punycode encoding, potentially hiding Unicode character substitution`,
        verified: true,
        severity: 'HIGH',
      });
    }

    // ─ 5. Free email provider for business context ──────
    if (this._isFreeEmailProvider(senderDomain) && this._appearsBusinessContext(displayName, emailData.subject)) {
      evidence.push({
        signal: 'unusual_sender',
        finding: `Business communication sent from free email provider "${senderDomain}" rather than a corporate domain`,
        verified: true,
        severity: 'MEDIUM',
      });
    }

    // ─ 6. Executive keyword in display name ─────────────
    const execKeyword = this._findExecutiveKeyword(displayName);
    if (execKeyword && this._isFreeEmailProvider(senderDomain)) {
      evidence.push({
        signal: 'executive_impersonation',
        finding: `Display name contains executive title "${execKeyword}" but email originates from free email provider "${senderDomain}"`,
        verified: true,
        severity: 'HIGH',
      });
    }

    // ─ 7. No legitimate signals ─────────────────────────
    if (evidence.length === 0) {
      evidence.push({
        signal: 'sender_appears_normal',
        finding: `Sender domain "${senderDomain}" appears consistent with the claimed sender identity`,
        verified: true,
        severity: 'NONE',
      });
    }

    return evidence;
  },

  _extractDomain(email) {
    if (!email || !email.includes('@')) return email;
    return email.split('@')[1].split('>')[0].trim();
  },

  _checkDisplayNameMismatch(displayName, senderDomain) {
    if (!displayName || !senderDomain) return false;
    // Check if the display name contains a domain that doesn't match the sender domain
    const domainInName = displayName.match(/([a-z0-9-]+\.[a-z]{2,})/i);
    if (domainInName) {
      const claimedDomain = domainInName[0].toLowerCase();
      if (claimedDomain !== senderDomain && !senderDomain.includes(claimedDomain)) {
        return true;
      }
    }
    return false;
  },

  _checkBrandImpersonation(displayName, senderDomain) {
    for (const [brand, domains] of Object.entries(this.BRAND_DOMAINS)) {
      const brandInName = displayName.includes(brand);
      const isLegitDomain = domains.some(d => senderDomain === d || senderDomain.endsWith('.' + d));
      if (brandInName && !isLegitDomain) {
        return { claimedBrand: brand, expectedDomains: domains };
      }
    }
    return null;
  },

  _checkTyposquatting(senderDomain) {
    if (!senderDomain) return null;
    const base = senderDomain.split('.')[0];
    const parts = [base, ...base.split('-')];
    const allLegitDomains = Object.values(this.BRAND_DOMAINS).flat();

    for (const part of parts) {
      if (!part) continue;
      for (const legitDomain of allLegitDomains) {
        const canonicalBase = legitDomain.split('.')[0];
        if (part === canonicalBase) continue;
        if (this._editDistance(part, canonicalBase) <= 2) {
          return { targetDomain: legitDomain };
        }
      }
    }
    return null;
  },

  _editDistance(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
      }
    }
    return dp[m][n];
  },

  _isFreeEmailProvider(domain) {
    return this.FREE_EMAIL_PROVIDERS.includes(domain);
  },

  _appearsBusinessContext(displayName, subject) {
    const bizKeywords = ['invoice', 'payment', 'account', 'urgent', 'transfer', 'wire', 'banking', 'office', 'team', 'hr'];
    const combined = `${displayName} ${subject || ''}`.toLowerCase();
    return bizKeywords.some(k => combined.includes(k));
  },

  _findExecutiveKeyword(displayName) {
    const lower = displayName.toLowerCase();
    return this.EXECUTIVE_KEYWORDS.find(k => lower.includes(k)) || null;
  },
};

if (typeof window !== 'undefined') window.SenderDetector = SenderDetector;
