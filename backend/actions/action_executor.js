// ============================================================
// ACTION EXECUTOR & AUDIT LOG — Backend Module
// Executes policy decisions across Demo Mailbox and Live Gmail.
// Safely manages quarantine, restore, spam, and audit logging.
// ============================================================

export class ActionExecutor {
  constructor(demoMailboxService, gmailService) {
    this.demoMailboxService = demoMailboxService;
    this.gmailService = gmailService;
    this.auditLog = [];
    this.quarantineStore = new Map(); // id -> { email, investigation, timestamp, restored }
  }

  async execute({ email, investigation, policyDecision, isLive = false }) {
    const timestamp = new Date().toISOString();
    const action = policyDecision.policy_decision;
    const emailId = email.id || `msg_${Date.now()}`;

    let executionResult = { success: true, action_taken: action };

    // Record to Quarantine Store if action is QUARANTINE
    if (action === 'QUARANTINE') {
      this.quarantineStore.set(emailId, {
        id: emailId,
        email,
        investigation,
        timestamp,
        restored: false,
        restored_at: null,
      });
    }

    if (isLive && this.gmailService && this.gmailService.isAuthenticated()) {
      try {
        if (action === 'QUARANTINE') {
          await this.gmailService.quarantineMessage(emailId);
        } else if (action === 'SPAM') {
          await this.gmailService.markAsSpam(emailId);
        } else if (action === 'ALLOW') {
          await this.gmailService.markAsSafe(emailId);
        }
      } catch (err) {
        executionResult = { success: false, error: err.message };
      }
    } else if (this.demoMailboxService) {
      // Execute within Demo Mailbox
      if (action === 'QUARANTINE') {
        this.demoMailboxService.moveToFolder(emailId, 'quarantine');
      } else if (action === 'SPAM') {
        this.demoMailboxService.moveToFolder(emailId, 'spam');
      } else {
        this.demoMailboxService.moveToFolder(emailId, 'inbox');
      }
    }

    // ── Create Audit Log Record ──────────────────────────────
    const auditRecord = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      email_id: emailId,
      subject: email.subject,
      sender: email.from_email || email.from_raw,
      timestamp,
      threat_category: investigation.primary_category ? investigation.primary_category.name : 'SAFE',
      risk_score: investigation.risk_score,
      ai_recommendation: investigation.recommended_action,
      policy_decision: policyDecision.policy_decision,
      executed_action: action,
      reason: policyDecision.reason,
      mode: isLive ? 'LIVE' : 'DEMO',
      execution_status: executionResult.success ? 'SUCCESS' : 'FAILED',
    };

    this.auditLog.unshift(auditRecord);
    // Keep max 500 records in memory
    if (this.auditLog.length > 500) this.auditLog.pop();

    return {
      action,
      auditRecord,
      quarantined: action === 'QUARANTINE',
      restored: false,
    };
  }

  async restoreFromQuarantine(emailId, isLive = false) {
    const item = this.quarantineStore.get(emailId);
    if (!item) {
      // Fallback check in demo mailbox
      if (this.demoMailboxService) {
        const demoMsg = this.demoMailboxService.getMessage(emailId);
        if (demoMsg) {
          this.demoMailboxService.moveToFolder(emailId, 'inbox');
          return { success: true, message: 'Message restored to Inbox in Demo Mailbox' };
        }
      }
      return { success: false, error: 'Message not found in quarantine store' };
    }

    item.restored = true;
    item.restored_at = new Date().toISOString();

    if (isLive && this.gmailService && this.gmailService.isAuthenticated()) {
      await this.gmailService.restoreMessage(emailId);
    } else if (this.demoMailboxService) {
      this.demoMailboxService.moveToFolder(emailId, 'inbox');
    }

    // Log restore in audit
    this.auditLog.unshift({
      id: `audit_restore_${Date.now()}`,
      email_id: emailId,
      subject: item.email.subject,
      sender: item.email.from_email || item.email.from_raw,
      timestamp: new Date().toISOString(),
      threat_category: item.investigation.primary_category ? item.investigation.primary_category.name : 'UNKNOWN',
      risk_score: item.investigation.risk_score,
      ai_recommendation: 'RESTORE_REQUESTED',
      policy_decision: 'USER_OVERRIDE_RESTORE',
      executed_action: 'RESTORED_TO_INBOX',
      reason: 'User manual override: message verified safe by recipient and restored to inbox.',
      mode: isLive ? 'LIVE' : 'DEMO',
      execution_status: 'SUCCESS',
    });

    return { success: true, message: 'Message successfully restored to Inbox', item };
  }

  getQuarantinedItems() {
    return Array.from(this.quarantineStore.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }

  getAuditLog(limit = 100) {
    return this.auditLog.slice(0, limit);
  }
}
