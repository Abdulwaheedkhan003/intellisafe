// ============================================================
// GMAIL SERVICE — Live Integration Module
// Handles OAuth 2.0 flow, token storage, and REST API operations
// with Google Gmail API (v1).
// ============================================================

import { NormalizedEmail } from '../schemas/email_schema.js';

export class GmailService {
  constructor(config = {}) {
    this.clientId = config.clientId || process.env.GMAIL_CLIENT_ID || '';
    this.clientSecret = config.clientSecret || process.env.GMAIL_CLIENT_SECRET || '';
    this.redirectUri = config.redirectUri || 'http://localhost:3000/api/gmail/oauth2callback';
    this.tokens = null;
    this.accountEmail = null;
    this.labelCache = new Map(); // name -> id
  }

  setCredentials({ clientId, clientSecret, redirectUri }) {
    if (clientId) this.clientId = clientId;
    if (clientSecret) this.clientSecret = clientSecret;
    if (redirectUri) this.redirectUri = redirectUri;
  }

  isAuthenticated() {
    return Boolean(this.tokens && this.tokens.access_token);
  }

  getStatus() {
    return {
      is_authenticated: this.isAuthenticated(),
      account_email: this.accountEmail || (this.isAuthenticated() ? 'Connected Gmail Account' : null),
      has_client_credentials: Boolean(this.clientId && this.clientSecret),
      redirect_uri: this.redirectUri,
    };
  }

  getAuthUrl() {
    if (!this.clientId) {
      // Fallback demo auth URL format if credentials not set yet
      return `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(this.clientId || 'YOUR_GMAIL_CLIENT_ID')}&redirect_uri=${encodeURIComponent(this.redirectUri)}&response_type=code&scope=https://mail.google.com/&access_type=offline&prompt=consent`;
    }
    const scopes = encodeURIComponent('https://mail.google.com/ email profile');
    return `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(this.clientId)}&redirect_uri=${encodeURIComponent(this.redirectUri)}&response_type=code&scope=${scopes}&access_type=offline&prompt=consent`;
  }

  async handleOAuthCallback(code) {
    try {
      const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: this.clientId,
          client_secret: this.clientSecret,
          redirect_uri: this.redirectUri,
          grant_type: 'authorization_code',
        }),
      });

      const data = await response.json();
      if (data.error) {
        throw new Error(data.error_description || data.error);
      }

      this.tokens = data;

      // Fetch user profile
      await this._fetchUserProfile();
      // Ensure required labels exist in user's mailbox
      await this._ensureLabels();

      return { success: true, account: this.accountEmail };
    } catch (err) {
      console.error('[GmailService] OAuth error:', err.message);
      return { success: false, error: err.message };
    }
  }

  async _fetchUserProfile() {
    try {
      const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
        headers: { Authorization: `Bearer ${this.tokens.access_token}` },
      });
      if (res.ok) {
        const profile = await res.json();
        this.accountEmail = profile.emailAddress;
      }
    } catch (e) {
      console.warn('[GmailService] Profile fetch failed:', e.message);
    }
  }

  async _ensureLabels() {
    if (!this.isAuthenticated()) return;
    const required = ['ThreatLens/Quarantine', 'ThreatLens/Safe', 'ThreatLens/Suspicious'];

    try {
      const listRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/labels', {
        headers: { Authorization: `Bearer ${this.tokens.access_token}` },
      });
      const data = await listRes.json();
      const existing = data.labels || [];

      for (const l of existing) {
        this.labelCache.set(l.name, l.id);
      }

      for (const reqName of required) {
        if (!this.labelCache.has(reqName)) {
          const createRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/labels', {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${this.tokens.access_token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              name: reqName,
              labelListVisibility: 'labelShow',
              messageListVisibility: 'show',
            }),
          });
          if (createRes.ok) {
            const created = await createRes.json();
            this.labelCache.set(created.name, created.id);
          }
        }
      }
    } catch (e) {
      console.warn('[GmailService] Label creation error:', e.message);
    }
  }

  async listRecentMessages(maxResults = 20) {
    if (!this.isAuthenticated()) return [];

    try {
      const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}&q=in:inbox`, {
        headers: { Authorization: `Bearer ${this.tokens.access_token}` },
      });
      const data = await res.json();
      const messageIds = (data.messages || []).map(m => m.id);

      const parsedEmails = [];
      for (const id of messageIds) {
        const fullMsg = await this.fetchMessage(id);
        if (fullMsg) parsedEmails.push(fullMsg);
      }
      return parsedEmails;
    } catch (err) {
      console.error('[GmailService] listRecentMessages failed:', err.message);
      return [];
    }
  }

  async fetchMessage(messageId) {
    if (!this.isAuthenticated()) return null;

    try {
      const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`, {
        headers: { Authorization: `Bearer ${this.tokens.access_token}` },
      });
      if (!res.ok) return null;
      const raw = await res.json();
      return this._parseGmailMessage(raw);
    } catch (err) {
      console.error(`[GmailService] fetchMessage ${messageId} failed:`, err.message);
      return null;
    }
  }

  _parseGmailMessage(raw) {
    const headers = {};
    for (const h of (raw.payload?.headers || [])) {
      headers[h.name.toLowerCase()] = h.value;
    }

    let bodyText = '';
    let bodyHtml = '';

    if (raw.payload?.parts) {
      for (const part of raw.payload.parts) {
        if (part.mimeType === 'text/plain' && part.body?.data) {
          bodyText += Buffer.from(part.body.data, 'base64').toString('utf8');
        } else if (part.mimeType === 'text/html' && part.body?.data) {
          bodyHtml += Buffer.from(part.body.data, 'base64').toString('utf8');
        }
      }
    } else if (raw.payload?.body?.data) {
      bodyText = Buffer.from(raw.payload.body.data, 'base64').toString('utf8');
    }

    return new NormalizedEmail({
      id: raw.id,
      thread_id: raw.threadId,
      subject: headers['subject'] || '(No Subject)',
      from_raw: headers['from'] || '',
      to_email: headers['to'] || '',
      reply_to: headers['reply-to'] || null,
      date: headers['date'] || new Date().toISOString(),
      body_text: bodyText,
      body_html: bodyHtml,
      spf: this._extractHeaderAuth(headers['authentication-results'], 'spf'),
      dkim: this._extractHeaderAuth(headers['authentication-results'], 'dkim'),
      dmarc: this._extractHeaderAuth(headers['authentication-results'], 'dmarc'),
      raw_headers: JSON.stringify(headers),
      is_demo: false,
    });
  }

  _extractHeaderAuth(authResults = '', protocol) {
    if (!authResults) return 'NONE';
    const match = authResults.match(new RegExp(`${protocol}=([a-z]+)`, 'i'));
    return match ? match[1].toUpperCase() : 'NONE';
  }

  async quarantineMessage(messageId) {
    const qLabelId = this.labelCache.get('ThreatLens/Quarantine');
    return this._modifyMessageLabels(messageId, {
      addLabelIds: qLabelId ? [qLabelId] : [],
      removeLabelIds: ['INBOX'],
    });
  }

  async markAsSpam(messageId) {
    return this._modifyMessageLabels(messageId, {
      addLabelIds: ['SPAM'],
      removeLabelIds: ['INBOX'],
    });
  }

  async markAsSafe(messageId) {
    const sLabelId = this.labelCache.get('ThreatLens/Safe');
    return this._modifyMessageLabels(messageId, {
      addLabelIds: sLabelId ? [sLabelId] : [],
      removeLabelIds: [],
    });
  }

  async restoreMessage(messageId) {
    const qLabelId = this.labelCache.get('ThreatLens/Quarantine');
    return this._modifyMessageLabels(messageId, {
      addLabelIds: ['INBOX'],
      removeLabelIds: qLabelId ? [qLabelId] : [],
    });
  }

  async _modifyMessageLabels(messageId, { addLabelIds = [], removeLabelIds = [] }) {
    if (!this.isAuthenticated()) return { success: false, error: 'Not authenticated' };

    try {
      const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/modify`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.tokens.access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ addLabelIds, removeLabelIds }),
      });
      return { success: res.ok, status: res.status };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  disconnect() {
    this.tokens = null;
    this.accountEmail = null;
    return { success: true };
  }
}
