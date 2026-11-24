// ============================================================
// DEMO MAILBOX SERVICE — Backend Module
// In-memory simulation of a full Gmail Mailbox (Inbox, Quarantine, Spam, Trash)
// Supports sample ingestion, folder navigation, and state mutation.
// ============================================================

import { SAMPLE_EMAILS } from '../data/sample_emails.js';
import { NormalizedEmail } from '../schemas/email_schema.js';

export class DemoMailboxService {
  constructor() {
    this.folders = {
      inbox: [],
      quarantine: [],
      spam: [],
      trash: [],
    };
    this.investigations = new Map(); // emailId -> investigationResult
    this.initDefaultMailbox();
  }

  initDefaultMailbox() {
    // Populate inbox with copy of sample emails
    for (const sample of SAMPLE_EMAILS) {
      const email = new NormalizedEmail(sample);
      this.folders.inbox.push(email);
    }
  }

  getFolder(folderName) {
    const list = this.folders[folderName] || [];
    return list.map(e => {
      const inv = this.investigations.get(e.id);
      return {
        ...e,
        investigation: inv || null,
        risk_score: inv ? inv.risk_score : null,
        primary_category: inv ? inv.primary_category : null,
      };
    });
  }

  getMessage(id) {
    for (const [folder, list] of Object.entries(this.folders)) {
      const msg = list.find(m => m.id === id);
      if (msg) {
        const inv = this.investigations.get(id);
        return {
          ...msg,
          current_folder: folder,
          investigation: inv || null,
        };
      }
    }
    return null;
  }

  recordInvestigation(emailId, investigationResult) {
    this.investigations.set(emailId, investigationResult);
  }

  getInvestigation(emailId) {
    return this.investigations.get(emailId) || null;
  }

  getAllInvestigations() {
    return Array.from(this.investigations.entries()).map(([id, inv]) => ({
      email_id: id,
      ...inv,
    }));
  }

  moveToFolder(emailId, targetFolder) {
    let foundMsg = null;
    for (const [folder, list] of Object.entries(this.folders)) {
      const idx = list.findIndex(m => m.id === emailId);
      if (idx !== -1) {
        foundMsg = list.splice(idx, 1)[0];
        break;
      }
    }

    if (foundMsg && this.folders[targetFolder]) {
      this.folders[targetFolder].unshift(foundMsg);
      return { success: true, folder: targetFolder, message: foundMsg };
    }

    return { success: false, error: 'Message or folder not found' };
  }

  resetMailbox() {
    this.folders = {
      inbox: [],
      quarantine: [],
      spam: [],
      trash: [],
    };
    this.investigations.clear();
    this.initDefaultMailbox();
    return { success: true, count: this.folders.inbox.length };
  }

  injectCustomEmail(emailData) {
    const email = new NormalizedEmail(emailData);
    this.folders.inbox.unshift(email);
    return email;
  }
}
