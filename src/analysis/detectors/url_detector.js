// ============================================================
// URL DETECTOR
// Extracts and analyses all URLs in the email body for
// malicious indicators: IP-based, obfuscated, shorteners,
// lookalike domains, and credential-harvesting destinations.
// ============================================================

const UrlDetector = {

  URL_SHORTENERS: [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'dlvr.it',
    'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
    'tr.im', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'short.ie',
    'zip.link', 'cutt.ly', 'shorturl.at', 'rb.gy', 'shortlinks.co',
  ],

  SUSPICIOUS_TLDS: [
    '.xyz', '.top', '.club', '.online', '.site', '.icu', '.live', '.tk', '.ml',
    '.ga', '.cf', '.gq', '.pw', '.ws', '.biz', '.info', '.mobi', '.cc',
  ],

  CREDENTIAL_KEYWORDS: [
    'login', 'signin', 'sign-in', 'account', 'verify', 'verification',
    'password', 'credential', 'secure', 'update', 'confirm', 'authenticate',
    'auth', 'recover', 'restore', 'unlock', 'validate',
  ],

  LOGIN_PAGE_PATTERNS: [
    /login\.php/, /signin\.php/, /account-verify/, /verify-account/,
    /credential-check/, /password-reset/, /secure-login/, /update-payment/,
    /account-suspended/, /unusual-activity/, /security-alert/,
  ],

  analyze(emailData) {
    const evidence = [];
    const urls = this._extractUrls(emailData);

    if (urls.length === 0) {
      return evidence;
    }

    const urlFindings = [];

    for (const url of urls) {
      const parsed = this._parseUrl(url);
      if (!parsed) continue;

      const urlEvidence = this._analyzeUrl(url, parsed, emailData);
      urlFindings.push(...urlEvidence);
    }

    // Deduplicate by signal type
    const seen = new Set();
    for (const finding of urlFindings) {
      const key = finding.signal + ':' + finding.finding;
      if (!seen.has(key)) {
        seen.add(key);
        evidence.push(finding);
      }
    }

    // If no suspicious URLs found, confirm
    if (evidence.length === 0) {
      evidence.push({
        signal: 'urls_appear_normal',
        finding: `${urls.length} URL(s) analysed — no malicious indicators detected`,
        verified: true,
        severity: 'NONE',
      });
    }

    return evidence;
  },

  _analyzeUrl(rawUrl, parsed, emailData) {
    const evidence = [];
    const { protocol, hostname, pathname, href } = parsed;

    // ─ 1. IP-based URL ───────────────────────────────────
    if (this._isIpAddress(hostname)) {
      evidence.push({
        signal: 'ip_address_url',
        finding: `URL uses a raw IP address "${hostname}" instead of a domain name — a common indicator of malicious infrastructure`,
        verified: true,
        severity: 'HIGH',
        url: href,
      });
    }

    // ─ 2. URL Shortener ──────────────────────────────────
    if (this.URL_SHORTENERS.includes(hostname)) {
      evidence.push({
        signal: 'url_shortener',
        finding: `URL "${rawUrl}" uses a URL shortener service "${hostname}" to obscure its true destination`,
        verified: true,
        severity: 'MEDIUM',
        url: href,
      });
      evidence.push({ signal: 'obfuscated_url', finding: `URL destination hidden via shortener: ${hostname}`, verified: true, severity: 'MEDIUM', url: href });
    }

    // ─ 3. Suspicious TLD ────────────────────────────────
    const tld = '.' + hostname.split('.').pop();
    if (this.SUSPICIOUS_TLDS.includes(tld)) {
      evidence.push({
        signal: 'suspicious_domain',
        finding: `URL domain "${hostname}" uses a TLD (${tld}) commonly associated with malicious or free hosting services`,
        verified: true,
        severity: 'MEDIUM',
        url: href,
      });
    }

    // ─ 4. Punycode / IDN homograph ───────────────────────
    if (hostname.startsWith('xn--') || hostname.includes('xn--')) {
      evidence.push({
        signal: 'punycode_domain',
        finding: `URL domain "${hostname}" uses punycode encoding, potentially disguising Unicode character substitution`,
        verified: true,
        severity: 'HIGH',
        url: href,
      });
      evidence.push({ signal: 'homograph', finding: `Punycode domain detected in URL: ${hostname}`, verified: true, severity: 'HIGH', url: href });
    }

    // ─ 5. Fake login page patterns ───────────────────────
    const fullPath = hostname + pathname;
    const hasLoginPattern = this.LOGIN_PAGE_PATTERNS.some(p => p.test(fullPath));
    const hasCredKeyword = this.CREDENTIAL_KEYWORDS.some(k => fullPath.includes(k));

    if (hasLoginPattern || hasCredKeyword) {
      evidence.push({
        signal: 'fake_login_url',
        finding: `URL "${href}" contains patterns consistent with a credential-harvesting login page`,
        verified: true,
        severity: 'CRITICAL',
        url: href,
      });
      evidence.push({ signal: 'credential_request', finding: 'URL leads to a page requesting authentication credentials', verified: true, severity: 'CRITICAL' });
    }

    // ─ 6. Overly-long / heavily-nested subdomain ────────
    const subdomains = hostname.split('.').length - 2;
    if (subdomains >= 4) {
      evidence.push({
        signal: 'obfuscated_url',
        finding: `URL "${hostname}" has ${subdomains} subdomain levels, which is unusual and may indicate URL obfuscation`,
        verified: true,
        severity: 'MEDIUM',
        url: href,
      });
    }

    // ─ 7. Non-HTTPS (HTTP only) ──────────────────────────
    if (protocol === 'http:') {
      evidence.push({
        signal: 'suspicious_link',
        finding: `URL "${href}" uses insecure HTTP protocol — sensitive information submitted would not be encrypted`,
        verified: true,
        severity: 'LOW',
        url: href,
      });
    }

    // ─ 8. Percent-encoding abuse ─────────────────────────
    const percentEncoded = (href.match(/%[0-9a-f]{2}/gi) || []).length;
    if (percentEncoded > 5) {
      evidence.push({
        signal: 'obfuscated_url',
        finding: `URL "${href}" contains ${percentEncoded} percent-encoded characters, which may be used to obscure the true destination`,
        verified: true,
        severity: 'MEDIUM',
        url: href,
      });
      evidence.push({ signal: 'url_encoding_abuse', finding: `Excessive URL encoding detected (${percentEncoded} encoded chars)`, verified: true, severity: 'MEDIUM' });
    }

    // ─ 9. Domain mismatch with claimed brand ─────────────
    const claimedBrand = this._detectClaimedBrandInSender(emailData);
    if (claimedBrand && !this._isLegitBrandDomain(hostname, claimedBrand)) {
      const legitDomains = SenderDetector && SenderDetector.BRAND_DOMAINS[claimedBrand] ? SenderDetector.BRAND_DOMAINS[claimedBrand] : [];
      if (legitDomains.length > 0 && !legitDomains.some(d => hostname.endsWith(d))) {
        evidence.push({
          signal: 'suspicious_link',
          finding: `Email claims to be from "${claimedBrand}" but embedded URL points to "${hostname}" — not a known "${claimedBrand}" domain`,
          verified: true,
          severity: 'HIGH',
          url: href,
        });
      }
    }

    return evidence;
  },

  _extractUrls(emailData) {
    const urls = new Set();
    const sources = [
      emailData.html_body || '',
      emailData.text_body || '',
    ];

    for (const source of sources) {
      // Extract href attributes
      const hrefMatches = source.match(/href=["']([^"']+)["']/gi) || [];
      hrefMatches.forEach(m => {
        const url = m.replace(/href=["']/i, '').replace(/["']$/, '');
        if (url.startsWith('http')) urls.add(url);
      });

      // Extract bare URLs
      const bareUrls = source.match(/https?:\/\/[^\s<>"']+/gi) || [];
      bareUrls.forEach(u => urls.add(u));
    }

    return Array.from(urls).slice(0, 50); // Limit to 50 URLs
  },

  _parseUrl(url) {
    try {
      return new URL(url);
    } catch {
      return null;
    }
  },

  _isIpAddress(hostname) {
    // IPv4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
    // IPv6 (simplified)
    if (/^\[?[0-9a-f:]+\]?$/i.test(hostname) && hostname.includes(':')) return true;
    return false;
  },

  _detectClaimedBrandInSender(emailData) {
    if (!window.SenderDetector) return null;
    const displayName = (emailData.from_name || '').toLowerCase();
    for (const brand of Object.keys(SenderDetector.BRAND_DOMAINS)) {
      if (displayName.includes(brand)) return brand;
    }
    return null;
  },

  _isLegitBrandDomain(hostname, brand) {
    if (!window.SenderDetector) return false;
    const legitDomains = SenderDetector.BRAND_DOMAINS[brand] || [];
    return legitDomains.some(d => hostname === d || hostname.endsWith('.' + d));
  },
};

if (typeof window !== 'undefined') window.UrlDetector = UrlDetector;
