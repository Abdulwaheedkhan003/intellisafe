// ============================================================
// MONITORING WORKER — 24/7 Background Security Engine
// Operates autonomously regardless of browser extension state.
// Continually ingests, inspects, and safeguards email streams.
// ============================================================

import { NormalizedEmail } from '../schemas/email_schema.js';
import { SenderDetector } from '../detectors/sender_detector.js';
import { HeaderDetector } from '../detectors/header_detector.js';
import { UrlDetector } from '../detectors/url_detector.js';
import { ContentDetector } from '../detectors/content_detector.js';
import { AttachmentDetector } from '../detectors/attachment_detector.js';
import { EmailSecurityInvestigationAgent } from '../agent/investigation_agent.js';
import { PolicyEngine } from '../engine/policy_engine.js';
import { RiskEngine } from '../engine/risk_engine.js';

export class MonitoringWorker {
  constructor({ demoMailboxService, gmailService, actionExecutor, pollIntervalMs = 15000 }) {
    this.demoMailbox = demoMailboxService;
    this.gmailService = gmailService;
    this.actionExecutor = actionExecutor;
    this.agent = new EmailSecurityInvestigationAgent();
    this.pollIntervalMs = pollIntervalMs;
    this.timer = null;
    this.isRunning = false;
    this.startedAt = new Date().toISOString();
    this.stats = {
      total_scanned: 0,
      threats_detected: 0,
      quarantined_count: 0,
      spam_count: 0,
      safe_count: 0,
      last_scan_at: null,
      last_action: null,
    };
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log('[ThreatLens 24/7 Monitor] Background monitoring worker started.');
    
    // Initial scan of demo samples
    this._runScanCycle();
    
    this.timer = setInterval(() => {
      this._runScanCycle();
    }, this.pollIntervalMs);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.isRunning = false;
    console.log('[ThreatLens 24/7 Monitor] Background monitoring worker stopped.');
  }

  getStatus() {
    return {
      active: this.isRunning,
      status_label: this.isRunning ? 'PROTECTION ACTIVE' : 'PROTECTION PAUSED',
      uptime_since: this.startedAt,
      stats: this.stats,
      poll_interval_ms: this.pollIntervalMs,
      mode: this.gmailService?.isAuthenticated() ? 'LIVE_GMAIL' : 'DEMO_SIMULATION',
    };
  }

  async processEmail(rawEmailData, isLive = false) {
    const email = new NormalizedEmail(rawEmailData);

    // 1. Fast Local Deterministic Detectors
    const senderEvidence = SenderDetector.analyze(email);
    const headerEvidence = HeaderDetector.analyze(email);
    const urlEvidence = UrlDetector.analyze(email);
    const contentEvidence = ContentDetector.analyze(email);
    const attachmentEvidence = AttachmentDetector.analyze(email);

    const fastEvidence = [
      ...senderEvidence,
      ...headerEvidence,
      ...urlEvidence,
      ...contentEvidence,
      ...attachmentEvidence,
    ];

    // 2. AI Security Investigation Agent Reasoning Loop
    const agentResult = await this.agent.investigate(email, fastEvidence);

    // 3. Risk Engine Evaluation
    const severityMeta = RiskEngine.evaluate(agentResult.risk_score);

    // 4. Policy Engine Evaluation (Strict Separation)
    const policyDecision = PolicyEngine.evaluate(agentResult);

    // Build unified investigation result
    const fullResult = {
      email_id: email.id,
      email_subject: email.subject,
      email_from: email.from_email || email.from_raw,
      email_from_name: email.from_name,
      to_email: email.to_email,
      date: email.date,
      analysis_timestamp: new Date().toISOString(),
      is_threat: agentResult.is_threat,
      primary_category: agentResult.primary_category,
      secondary_categories: agentResult.secondary_categories,
      risk_score: agentResult.risk_score,
      severity: severityMeta,
      confidence_pct: Math.round(agentResult.confidence * 100),
      confidence: agentResult.confidence,
      explanation: agentResult.explanation,
      evidence: agentResult.evidence.filter(e => e.verified),
      recommended_action: agentResult.recommended_action,
      policy_decision: policyDecision.policy_decision,
      policy_reason: policyDecision.reason,
      investigation_timeline: agentResult.investigation_timeline,
      intel_status: agentResult.intel_status,
      is_demo: !isLive,
    };

    // 5. Action Executor (Quarantine, Spam, Allow, Audit Logging)
    const execution = await this.actionExecutor.execute({
      email,
      investigation: fullResult,
      policyDecision,
      isLive,
    });

    fullResult.executed_action = execution.action;
    fullResult.audit_record = execution.auditRecord;

    // Store in mailbox service
    if (this.demoMailbox) {
      this.demoMailbox.recordInvestigation(email.id, fullResult);
    }

    // Update global monitoring stats
    this.stats.total_scanned++;
    this.stats.last_scan_at = new Date().toISOString();
    this.stats.last_action = `${fullResult.executed_action} -> ${email.subject.slice(0, 30)}`;

    if (fullResult.is_threat) {
      this.stats.threats_detected++;
      if (execution.action === 'QUARANTINE') this.stats.quarantined_count++;
      if (execution.action === 'SPAM') this.stats.spam_count++;
    } else {
      this.stats.safe_count++;
    }

    return fullResult;
  }

  async _runScanCycle() {
    try {
      if (this.gmailService && this.gmailService.isAuthenticated()) {
        // LIVE GMAIL SCAN
        const messages = await this.gmailService.listRecentMessages(10);
        for (const msg of messages) {
          if (!this.demoMailbox.getInvestigation(msg.id)) {
            await this.processEmail(msg, true);
          }
        }
      } else if (this.demoMailbox) {
        // DEMO MAILBOX SCAN
        const inbox = this.demoMailbox.getFolder('inbox');
        for (const msg of inbox) {
          if (!this.demoMailbox.getInvestigation(msg.id)) {
            await this.processEmail(msg, false);
          }
        }
      }
    } catch (err) {
      console.error('[ThreatLens Monitor] Error during scan cycle:', err.message);
    }
  }
}
