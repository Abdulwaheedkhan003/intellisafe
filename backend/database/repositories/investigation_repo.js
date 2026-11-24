// ============================================================
// INVESTIGATION REPOSITORY
// Saves full investigation results with all evidence
// ============================================================

import { getDb } from '../db.js';

export class InvestigationRepo {
  static save(messageId, result, evidenceList) {
    const db = getDb();

    const secondary = result.secondary_categories
      ? JSON.stringify(result.secondary_categories)
      : '[]';
    const keyFactors = result.assessment?.key_factors
      ? JSON.stringify(result.assessment.key_factors)
      : '[]';
    const timeline = result.investigation_timeline
      ? JSON.stringify(result.investigation_timeline)
      : '[]';

    const inv = db.prepare(`
      INSERT INTO investigations (
        message_id, risk_score, severity, confidence,
        primary_category_id, primary_category_name,
        secondary_categories, ai_summary, ai_key_factors,
        human_explanation, recommended_action, policy_decision,
        executed_action, intel_status, investigation_timeline, is_threat
      ) VALUES (
        @message_id, @risk_score, @severity, @confidence,
        @primary_category_id, @primary_category_name,
        @secondary_categories, @ai_summary, @ai_key_factors,
        @human_explanation, @recommended_action, @policy_decision,
        @executed_action, @intel_status, @investigation_timeline, @is_threat
      )
    `).run({
      message_id: messageId,
      risk_score: result.risk_score || 0,
      severity: result.severity?.label || 'SAFE',
      confidence: result.confidence || 0,
      primary_category_id: result.primary_category?.id || null,
      primary_category_name: result.primary_category?.name || 'SAFE',
      secondary_categories: secondary,
      ai_summary: result.assessment?.summary || result.explanation || '',
      ai_key_factors: keyFactors,
      human_explanation: result.explanation || '',
      recommended_action: result.recommended_action || 'ALLOW',
      policy_decision: result.policy_decision || 'ALLOW',
      executed_action: result.executed_action || 'ALLOW',
      intel_status: result.intel_status || 'UNAVAILABLE',
      investigation_timeline: timeline,
      is_threat: result.is_threat ? 1 : 0,
    });

    const investigationId = inv.lastInsertRowid;

    // Save all evidence items
    if (evidenceList && evidenceList.length > 0) {
      const evStmt = db.prepare(`
        INSERT INTO evidence (
          investigation_id, type, signal, finding, value_json,
          source, severity, confidence, verified, verification_status
        ) VALUES (
          @investigation_id, @type, @signal, @finding, @value_json,
          @source, @severity, @confidence, @verified, @verification_status
        )
      `);
      const insertMany = db.transaction((items) => {
        for (const e of items) {
          evStmt.run({
            investigation_id: investigationId,
            type: e.type || 'UNKNOWN',
            signal: e.signal || '',
            finding: e.finding || '',
            value_json: e.value ? JSON.stringify(e.value) : null,
            source: e.source || 'detector',
            severity: e.severity || 'INFO',
            confidence: e.confidence || 0.5,
            verified: e.verified ? 1 : 0,
            verification_status: e.verification_status || 'VERIFIED',
          });
        }
      });
      insertMany(evidenceList);
    }

    return investigationId;
  }

  static findByMessageId(messageId) {
    const db = getDb();
    const inv = db.prepare('SELECT * FROM investigations WHERE message_id = ?').get(messageId);
    if (!inv) return null;
    inv.evidence = db.prepare('SELECT * FROM evidence WHERE investigation_id = ?').all(inv.id);
    try { inv.secondary_categories = JSON.parse(inv.secondary_categories || '[]'); } catch { inv.secondary_categories = []; }
    try { inv.ai_key_factors = JSON.parse(inv.ai_key_factors || '[]'); } catch { inv.ai_key_factors = []; }
    try { inv.investigation_timeline = JSON.parse(inv.investigation_timeline || '[]'); } catch { inv.investigation_timeline = []; }
    return inv;
  }

  static findById(id) {
    const db = getDb();
    const inv = db.prepare('SELECT * FROM investigations WHERE id = ?').get(id);
    if (!inv) return null;
    inv.evidence = db.prepare('SELECT * FROM evidence WHERE investigation_id = ?').all(inv.id);
    try { inv.secondary_categories = JSON.parse(inv.secondary_categories || '[]'); } catch { inv.secondary_categories = []; }
    try { inv.ai_key_factors = JSON.parse(inv.ai_key_factors || '[]'); } catch { inv.ai_key_factors = []; }
    try { inv.investigation_timeline = JSON.parse(inv.investigation_timeline || '[]'); } catch { inv.investigation_timeline = []; }
    return inv;
  }

  static findByGmailMessageId(gmailMessageId) {
    const db = getDb();
    const msg = db.prepare('SELECT id FROM messages WHERE gmail_message_id = ?').get(gmailMessageId);
    if (!msg) return null;
    return this.findByMessageId(msg.id);
  }

  static getRecent(limit = 50) {
    const db = getDb();
    return db.prepare(`
      SELECT i.*, m.gmail_message_id, m.subject, m.from_email, m.from_name, m.received_at
      FROM investigations i
      JOIN messages m ON i.message_id = m.id
      ORDER BY i.created_at DESC LIMIT ?
    `).all(limit);
  }

  static getStats() {
    const db = getDb();
    const total = db.prepare('SELECT COUNT(*) as c FROM messages').get().c;
    const threats = db.prepare('SELECT COUNT(*) as c FROM investigations WHERE is_threat = 1').get().c;
    const quarantined = db.prepare("SELECT COUNT(*) as c FROM investigations WHERE executed_action = 'QUARANTINE'").get().c;
    const spam = db.prepare("SELECT COUNT(*) as c FROM investigations WHERE executed_action = 'SPAM'").get().c;
    const flagged = db.prepare("SELECT COUNT(*) as c FROM investigations WHERE executed_action = 'FLAG'").get().c;
    const safe = db.prepare("SELECT COUNT(*) as c FROM investigations WHERE executed_action = 'ALLOW'").get().c;
    return { total_scanned: total, threats_detected: threats, quarantined, spam, flagged, safe };
  }
}
