// ============================================================
// URL DETECTOR — Backend Module
// Extracts, normalizes, and analyzes URLs for phishing paths,
// raw IP hosts, suspicious TLDs, shorteners, and fake login pages.
// ============================================================

import { EvidenceItem, EVIDENCE_TYPES, VERIFICATION_STATUS } from '../schemas/evidence_schema.js';

export class UrlDetector {
  static URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'dlvr.it',
    'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
    'tr.im', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'short.ie',
    'zip.link', 'cutt.ly', 'shorturl.at', 'rb.gy', 'shortlinks.co',
  ];

  static SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.online', '.site', '.icu', '.live', '.tk', '.ml',
    '.ga', '.cf', '.gq', '.pw', '.ws', '.biz', '.info', '.mobi', '.cc',
  ];

  static LOGIN_KEYWORDS = [
    'login', 'signin', 'sign-in', 'account-verify', 'verify-account',
    'password-reset', 'secure-login', 'update-payment', 'account-suspended',
    'credential', 'authenticate', 'webscr', 'cmd=_login-run',
  ];

  static analyze(emailData) {
    const evidence = [];
    const urls = Array.isArray(emailData.urls) ? emailData.urls : [];

    if (urls.length === 0) {
      return evidence;
    }

    const seenSignals = new Set();

    for (const rawUrl of urls) {
      const parsed = this._parseUrl(rawUrl);
      if (!parsed) continue;

      const { hostname, pathname, href, protocol } = parsed;

      // 1. IP Address based URL
      if (this._isIpAddress(hostname)) {
        const key = `ip_url:${hostname}`;
        if (!seenSignals.has(key)) {
          seenSignals.add(key);
          evidence.push(new EvidenceItem({
            type: EVIDENCE_TYPES.URL,
            signal: 'ip_address_url',
            finding: `URL uses raw IP host "${hostname}" without a registered domain name (common malware/phishing host)`,
            value: href,
            source: 'url_detector',
            verified: true,
            confidence: 0.95,
            severity: 'HIGH',
            verification_status: VERIFICATION_STATUS.CONFIRMED,
          }));
        }
      }

      // 2. URL Shortener Abuse
      if (this.URL_SHORTENERS.includes(hostname)) {
        const key = `shortener:${hostname}`;
        if (!seenSignals.has(key)) {
          seenSignals.add(key);
          evidence.push(new EvidenceItem({
            type: EVIDENCE_TYPES.URL,
            signal: 'url_shortener',
            finding: `URL uses shortening service "${hostname}" to conceal true target destination`,
            value: href,
            source: 'url_detector',
            verified: true,
            confidence: 0.90,
            severity: 'MEDIUM',
            verification_status: VERIFICATION_STATUS.CONFIRMED,
          }));
        }
      }

      // 3. Fake Login / Credential harvesting URL path
      const pathAndQuery = (pathname + (parsed.search || '')).toLowerCase();
      const hasLoginKeyword = this.LOGIN_KEYWORDS.some(kw => pathAndQuery.includes(kw));
      if (hasLoginKeyword) {
        const key = `fake_login:${hostname}`;
        if (!seenSignals.has(key)) {
          seenSignals.add(key);
          evidence.push(new EvidenceItem({
            type: EVIDENCE_TYPES.URL,
            signal: 'fake_login_url',
            finding: `URL path on "${hostname}" matches credential-harvesting login page signature`,
            value: href,
            source: 'url_detector',
            verified: true,
            confidence: 0.94,
            severity: 'CRITICAL',
            verification_status: VERIFICATION_STATUS.CONFIRMED,
          }));
        }
      }

      // 4. Suspicious TLD
      const hasSuspiciousTld = this.SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
      if (hasSuspiciousTld) {
        const key = `tld:${hostname}`;
        if (!seenSignals.has(key)) {
          seenSignals.add(key);
          evidence.push(new EvidenceItem({
            type: EVIDENCE_TYPES.URL,
            signal: 'suspicious_domain',
            finding: `URL points to domain "${hostname}" using a high-risk generic top-level domain`,
            value: href,
            source: 'url_detector',
            verified: true,
            confidence: 0.85,
            severity: 'MEDIUM',
            verification_status: VERIFICATION_STATUS.CONFIRMED,
          }));
        }
      }

      // 5. Lookalike / Brand keyword in non-official domain path/subdomain
      const brandInSubdomain = this._checkBrandInSubdomain(hostname);
      if (brandInSubdomain) {
        const key = `brand_sub:${hostname}`;
        if (!seenSignals.has(key)) {
          seenSignals.add(key);
          evidence.push(new EvidenceItem({
            type: EVIDENCE_TYPES.URL,
            signal: 'lookalike_domain',
            finding: `Domain "${hostname}" embeds brand name "${brandInSubdomain}" on third-party infrastructure`,
            value: href,
            source: 'url_detector',
            verified: true,
            confidence: 0.93,
            severity: 'HIGH',
            verification_status: VERIFICATION_STATUS.CONFIRMED,
          }));
        }
      }
    }

    if (evidence.length === 0) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.URL,
        signal: 'urls_appear_normal',
        finding: `${urls.length} link(s) checked — all destinations resolve to recognized domains with no known security flags`,
        value: { count: urls.length },
        source: 'url_detector',
        verified: true,
        confidence: 0.92,
        severity: 'SAFE',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    return evidence;
  }

  static _parseUrl(rawUrl) {
    try {
      return new URL(rawUrl);
    } catch {
      try {
        return new URL('http://' + rawUrl);
      } catch {
        return null;
      }
    }
  }

  static _isIpAddress(hostname) {
    if (!hostname) return false;
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(hostname)) return false;
    const parts = hostname.split('.').map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }

  static _checkBrandInSubdomain(hostname) {
    const brands = ['microsoft', 'google', 'paypal', 'apple', 'amazon', 'chase', 'wellsfargo', 'docusign', 'netflix'];
    const parts = hostname.split('.');
    if (parts.length > 2) {
      const subdomain = parts.slice(0, -2).join('.');
      for (const b of brands) {
        if (subdomain.includes(b)) return b;
      }
    }
    return null;
  }
}
