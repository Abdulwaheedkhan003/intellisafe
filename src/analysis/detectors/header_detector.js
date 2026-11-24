// ============================================================
// HEADER DETECTOR
// Analyses email headers for anomalies: auth failures, routing
// irregularities, spoofing indicators, and suspicious metadata.
// ============================================================

const HeaderDetector = {

  analyze(emailData) {
    const evidence = [];
    const headers = emailData.headers || {};
    const rawHeaders = emailData.raw_headers || '';

    // ─ 1. SPF Result ─────────────────────────────────────
    const spf = this._extractAuthResult(rawHeaders, 'spf') || headers['spf'] || null;
    if (spf) {
      if (spf.includes('fail')) {
        evidence.push({
          signal: 'spf_fail',
          finding: `SPF check FAILED — the sending server is not authorised to send email on behalf of this domain`,
          verified: true,
          severity: 'HIGH',
          auth_protocol: 'SPF',
          result: 'FAIL',
        });
        evidence.push({ signal: 'auth_failure', finding: 'Email authentication failed (SPF)', verified: true, severity: 'HIGH' });
      } else if (spf.includes('softfail')) {
        evidence.push({
          signal: 'spf_softfail',
          finding: `SPF check SOFTFAIL — the sending server may not be authorised to send for this domain`,
          verified: true,
          severity: 'MEDIUM',
          auth_protocol: 'SPF',
          result: 'SOFTFAIL',
        });
      } else if (spf.includes('pass')) {
        evidence.push({ signal: 'spf_pass', finding: 'SPF check passed', verified: true, severity: 'NONE', auth_protocol: 'SPF', result: 'PASS' });
      } else if (spf.includes('none')) {
        evidence.push({
          signal: 'spf_none',
          finding: 'No SPF record found for sender domain — the domain has not published SPF authentication information',
          verified: true,
          severity: 'LOW',
          auth_protocol: 'SPF',
          result: 'NONE',
        });
      }
    }

    // ─ 2. DKIM Result ────────────────────────────────────
    const dkim = this._extractAuthResult(rawHeaders, 'dkim') || headers['dkim'] || null;
    if (dkim) {
      if (dkim.includes('fail') && !dkim.includes('softfail')) {
        evidence.push({
          signal: 'dkim_fail',
          finding: `DKIM signature FAILED — the email content may have been tampered with in transit`,
          verified: true,
          severity: 'HIGH',
          auth_protocol: 'DKIM',
          result: 'FAIL',
        });
      } else if (dkim.includes('pass')) {
        evidence.push({ signal: 'dkim_pass', finding: 'DKIM signature is valid', verified: true, severity: 'NONE', auth_protocol: 'DKIM', result: 'PASS' });
      } else if (dkim.includes('none')) {
        evidence.push({
          signal: 'dkim_none',
          finding: 'No DKIM signature found — the email was not cryptographically signed by the sender\'s domain',
          verified: true,
          severity: 'LOW',
          auth_protocol: 'DKIM',
          result: 'NONE',
        });
      }
    }

    // ─ 3. DMARC Result ───────────────────────────────────
    const dmarc = this._extractAuthResult(rawHeaders, 'dmarc') || headers['dmarc'] || null;
    if (dmarc) {
      if (dmarc.includes('fail')) {
        evidence.push({
          signal: 'dmarc_fail',
          finding: `DMARC policy check FAILED — this email fails domain-based message authentication and may be spoofed`,
          verified: true,
          severity: 'HIGH',
          auth_protocol: 'DMARC',
          result: 'FAIL',
        });
      } else if (dmarc.includes('pass')) {
        evidence.push({ signal: 'dmarc_pass', finding: 'DMARC policy check passed', verified: true, severity: 'NONE', auth_protocol: 'DMARC', result: 'PASS' });
      } else if (dmarc.includes('none')) {
        evidence.push({
          signal: 'dmarc_none',
          finding: 'No DMARC policy found for sender domain',
          verified: true,
          severity: 'LOW',
          auth_protocol: 'DMARC',
          result: 'NONE',
        });
      }
    }

    // ─ 4. Reply-To mismatch ──────────────────────────────
    const replyTo = headers['reply-to'] || this._extractHeader(rawHeaders, 'Reply-To');
    const fromEmail = emailData.from_email || '';
    if (replyTo && fromEmail) {
      const replyDomain = this._extractDomain(replyTo);
      const fromDomain = this._extractDomain(fromEmail);
      if (replyDomain && fromDomain && replyDomain !== fromDomain) {
        evidence.push({
          signal: 'header_anomaly',
          finding: `Reply-To domain "${replyDomain}" differs from the From domain "${fromDomain}" — replies will be directed to a different organisation`,
          verified: true,
          severity: 'HIGH',
        });
      }
    }

    // ─ 5. Return-Path mismatch ───────────────────────────
    const returnPath = headers['return-path'] || this._extractHeader(rawHeaders, 'Return-Path');
    if (returnPath && fromEmail) {
      const returnDomain = this._extractDomain(returnPath);
      const fromDomain = this._extractDomain(fromEmail);
      if (returnDomain && fromDomain && returnDomain !== fromDomain) {
        evidence.push({
          signal: 'header_anomaly',
          finding: `Return-Path domain "${returnDomain}" does not match the From domain "${fromDomain}"`,
          verified: true,
          severity: 'MEDIUM',
        });
      }
    }

    // ─ 6. Suspicious X-Mailer / User-Agent ──────────────
    const xMailer = headers['x-mailer'] || this._extractHeader(rawHeaders, 'X-Mailer');
    if (xMailer) {
      const suspiciousMailers = ['massmailer', 'phpmailer', 'sendblaster', 'atomic mail'];
      if (suspiciousMailers.some(m => xMailer.toLowerCase().includes(m))) {
        evidence.push({
          signal: 'bulk_sender',
          finding: `Email was sent using bulk/mass-mailing software: "${xMailer}"`,
          verified: true,
          severity: 'MEDIUM',
        });
      }
    }

    // ─ 7. Received header routing anomalies ─────────────
    const receivedChain = this._extractAllReceived(rawHeaders);
    if (receivedChain.length > 6) {
      evidence.push({
        signal: 'route_anomaly',
        finding: `Email passed through ${receivedChain.length} mail relay hops — an unusually high number that may indicate routing obfuscation`,
        verified: true,
        severity: 'MEDIUM',
      });
    }

    // ─ 8. Tracking pixel / reconnaissance indicators ─────
    if (emailData.html_body && emailData.html_body.includes('<img') && emailData.html_body.match(/<img[^>]+src=["'][^"']{1,100}["'][^>]*>/)) {
      // Check for 1x1 pixel images (tracking)
      if (emailData.html_body.match(/width=["']?1["']?[^>]*height=["']?1["']?/i) ||
          emailData.html_body.match(/height=["']?1["']?[^>]*width=["']?1["']?/i)) {
        evidence.push({
          signal: 'tracking_pixel',
          finding: 'Email contains a tracking pixel designed to notify the sender when the email is opened (reconnaissance)',
          verified: true,
          severity: 'LOW',
        });
        evidence.push({ signal: 'open_rate_tracking', finding: 'Email open tracking detected', verified: true, severity: 'LOW' });
      }
    }

    // ─ 9. Missing Message-ID ─────────────────────────────
    const messageId = headers['message-id'] || this._extractHeader(rawHeaders, 'Message-ID');
    if (!messageId) {
      evidence.push({
        signal: 'header_anomaly',
        finding: 'Email is missing a Message-ID header — legitimate emails always include this header',
        verified: true,
        severity: 'MEDIUM',
      });
    }

    return evidence;
  },

  _extractAuthResult(rawHeaders, protocol) {
    if (!rawHeaders) return null;
    const match = rawHeaders.match(new RegExp(`${protocol}=([^;\\s]+)`, 'i'));
    return match ? match[1].toLowerCase() : null;
  },

  _extractHeader(rawHeaders, headerName) {
    if (!rawHeaders) return null;
    const match = rawHeaders.match(new RegExp(`^${headerName}:\\s*(.+)$`, 'im'));
    return match ? match[1].trim() : null;
  },

  _extractAllReceived(rawHeaders) {
    if (!rawHeaders) return [];
    return (rawHeaders.match(/^Received:/gim) || []);
  },

  _extractDomain(emailOrAddress) {
    if (!emailOrAddress) return null;
    const cleaned = emailOrAddress.replace(/[<>]/g, '').trim();
    if (cleaned.includes('@')) return cleaned.split('@')[1].toLowerCase();
    return null;
  },
};

if (typeof window !== 'undefined') window.HeaderDetector = HeaderDetector;
