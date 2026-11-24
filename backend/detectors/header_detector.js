// ============================================================
// HEADER DETECTOR — Backend Module
// Analyses email authentication records (SPF, DKIM, DMARC),
// routing hops, tracking pixels, and bulk mailer signatures.
// ============================================================

import { EvidenceItem, EVIDENCE_TYPES, VERIFICATION_STATUS } from '../schemas/evidence_schema.js';

export class HeaderDetector {
  static analyze(emailData) {
    const evidence = [];
    const headers = emailData.headers || {};
    const rawHeaders = (emailData.raw_headers || '').toLowerCase();
    
    // 1. SPF Result
    const spf = (emailData.spf || this._extractAuthResult(rawHeaders, 'spf') || headers['spf'] || '').toLowerCase();
    if (spf) {
      if (spf.includes('fail') && !spf.includes('softfail')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'spf_fail',
          finding: 'SPF authentication check FAILED — sending server is not authorized to send for this domain',
          value: { protocol: 'SPF', result: 'FAIL' },
          source: 'header_detector',
          verified: true,
          confidence: 0.98,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      } else if (spf.includes('softfail')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'spf_softfail',
          finding: 'SPF check returned SOFTFAIL — sender may not be authorized by domain policy',
          value: { protocol: 'SPF', result: 'SOFTFAIL' },
          source: 'header_detector',
          verified: true,
          confidence: 0.85,
          severity: 'MEDIUM',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      } else if (spf.includes('pass')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'spf_pass',
          finding: 'SPF authentication check PASSED',
          value: { protocol: 'SPF', result: 'PASS' },
          source: 'header_detector',
          verified: true,
          confidence: 1.0,
          severity: 'SAFE',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      } else if (spf.includes('none')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'spf_none',
          finding: 'No SPF record published for sender domain',
          value: { protocol: 'SPF', result: 'NONE' },
          source: 'header_detector',
          verified: true,
          confidence: 0.90,
          severity: 'LOW',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    // 2. DKIM Result
    const dkim = (emailData.dkim || this._extractAuthResult(rawHeaders, 'dkim') || headers['dkim'] || '').toLowerCase();
    if (dkim) {
      if (dkim.includes('fail') && !dkim.includes('softfail')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'dkim_fail',
          finding: 'DKIM cryptographic signature FAILED — message content or headers may have been altered',
          value: { protocol: 'DKIM', result: 'FAIL' },
          source: 'header_detector',
          verified: true,
          confidence: 0.98,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      } else if (dkim.includes('pass')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'dkim_pass',
          finding: 'DKIM cryptographic signature is valid and PASSED',
          value: { protocol: 'DKIM', result: 'PASS' },
          source: 'header_detector',
          verified: true,
          confidence: 1.0,
          severity: 'SAFE',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      } else if (dkim.includes('none')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'dkim_none',
          finding: 'No DKIM signature found on email message',
          value: { protocol: 'DKIM', result: 'NONE' },
          source: 'header_detector',
          verified: true,
          confidence: 0.90,
          severity: 'LOW',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    // 3. DMARC Result
    const dmarc = (emailData.dmarc || this._extractAuthResult(rawHeaders, 'dmarc') || headers['dmarc'] || '').toLowerCase();
    if (dmarc) {
      if (dmarc.includes('fail')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'dmarc_fail',
          finding: 'DMARC alignment check FAILED — email fails domain-level alignment policy',
          value: { protocol: 'DMARC', result: 'FAIL' },
          source: 'header_detector',
          verified: true,
          confidence: 0.99,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      } else if (dmarc.includes('pass')) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.AUTH,
          signal: 'dmarc_pass',
          finding: 'DMARC alignment check PASSED',
          value: { protocol: 'DMARC', result: 'PASS' },
          source: 'header_detector',
          verified: true,
          confidence: 1.0,
          severity: 'SAFE',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    // 4. Tracking Pixels (1x1 images)
    if (emailData.body_html) {
      const pixelRegex = /<img[^>]+(?:width=['"]?1['"]?|height=['"]?1['"]?|display:\s*none)[^>]*>/i;
      if (pixelRegex.test(emailData.body_html)) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.BEHAVIORAL,
          signal: 'tracking_pixel',
          finding: 'Tracking pixel (1x1 transparent image) detected in HTML body — email open tracking/reconnaissance',
          value: null,
          source: 'header_detector',
          verified: true,
          confidence: 0.85,
          severity: 'INFO',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    // 5. Bulk mailer header check
    const xMailer = headers['x-mailer'] || headers['x-php-originating-script'] || '';
    if (/mass|bulk|blast|phplist|sendblaster/i.test(xMailer)) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.HEADER,
        signal: 'bulk_sender',
        finding: `Bulk mailing software signature detected in X-Mailer header: "${xMailer}"`,
        value: xMailer,
        source: 'header_detector',
        verified: true,
        confidence: 0.88,
        severity: 'MEDIUM',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    return evidence;
  }

  static _extractAuthResult(rawHeaders, protocol) {
    if (!rawHeaders) return null;
    const authRegex = new RegExp(`authentication-results:[^\\n]*(?:\\n\\s+[^\\n]*)*${protocol}=([a-z]+)`, 'i');
    const match = rawHeaders.match(authRegex);
    return match ? match[1] : null;
  }
}
