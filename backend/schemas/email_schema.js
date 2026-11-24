// ============================================================
// EMAIL SCHEMA & NORMALIZER
// Provides consistent structure for parsed email data
// ============================================================

export class NormalizedEmail {
  constructor(data = {}) {
    this.id = data.id || `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.thread_id = data.thread_id || null;
    this.subject = data.subject || '(No Subject)';
    this.from_raw = data.from_raw || data.from || '';
    this.from_email = data.from_email || this._extractEmail(this.from_raw);
    this.from_name = data.from_name || this._extractName(this.from_raw);
    this.to_email = data.to_email || data.to || '';
    this.reply_to = data.reply_to || null;
    this.return_path = data.return_path || null;
    this.date = data.date || new Date().toISOString();
    
    // Body representations
    this.body_text = data.body_text || (typeof data.body === 'string' ? data.body : '');
    this.body_html = data.body_html || '';
    
    // Authentication headers (SPF, DKIM, DMARC)
    this.spf = (data.spf || 'NONE').toUpperCase();
    this.dkim = (data.dkim || 'NONE').toUpperCase();
    this.dmarc = (data.dmarc || 'NONE').toUpperCase();
    this.auth_results = data.auth_results || data.authentication_results || '';

    // Extracted components
    this.urls = Array.isArray(data.urls) ? data.urls : this._extractUrls(this.body_text, this.body_html);
    this.attachments = Array.isArray(data.attachments) ? data.attachments : [];
    this.headers = data.headers && typeof data.headers === 'object' ? data.headers : {};
    
    // Metadata
    this.claimed_organization = data.claimed_organization || null;
    this.is_demo = Boolean(data.is_demo);
  }

  _extractEmail(raw) {
    if (!raw) return '';
    const match = raw.match(/<([^>]+)>/) || raw.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase().trim() : raw.toLowerCase().trim();
  }

  _extractName(raw) {
    if (!raw) return '';
    const match = raw.match(/^"?([^"<]+)"?\s*</);
    if (match) return match[1].trim();
    if (raw.includes('@')) {
      const email = this._extractEmail(raw);
      return email.split('@')[0];
    }
    return raw.trim();
  }

  _extractUrls(text = '', html = '') {
    const urlSet = new Set();
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
    
    let match;
    while ((match = urlRegex.exec(text)) !== null) {
      urlSet.add(match[0].replace(/[.,;!?)\]]+$/, ''));
    }
    while ((match = urlRegex.exec(html)) !== null) {
      urlSet.add(match[0].replace(/[.,;!?)\]]+$/, ''));
    }

    return Array.from(urlSet);
  }

  toJSON() {
    return {
      id: this.id,
      thread_id: this.thread_id,
      subject: this.subject,
      from_raw: this.from_raw,
      from_email: this.from_email,
      from_name: this.from_name,
      to_email: this.to_email,
      reply_to: this.reply_to,
      return_path: this.return_path,
      date: this.date,
      body_text: this.body_text,
      body_html: this.body_html,
      spf: this.spf,
      dkim: this.dkim,
      dmarc: this.dmarc,
      auth_results: this.auth_results,
      urls: this.urls,
      attachments: this.attachments,
      headers: this.headers,
      claimed_organization: this.claimed_organization,
      is_demo: this.is_demo,
    };
  }
}
