// ============================================================
// POLICY ENGINE — Backend Module
// Independent evaluation of risk score, category, confidence,
// evidence, and security rules.
// Enforces: AI recommends → Policy decides → Action executes.
// ============================================================

export class PolicyEngine {
  static DEFAULT_POLICY = {
    quarantine_risk_threshold: 70,
    quarantine_min_confidence: 0.75,
    spam_risk_threshold: 45,
    auto_quarantine_categories: [
      'PHISHING', 'SPEAR_PHISHING', 'WHALING', 'BEC', 'CEO_FRAUD',
      'CREDENTIAL_HARVESTING', 'MALWARE_DELIVERY', 'MALICIOUS_MACRO',
      'EXECUTABLE_ATTACHMENT', 'EXTORTION', 'BLACKMAIL', 'BANK_ACCOUNT_CHANGE',
      'PAYMENT_REDIRECTION', 'WIRE_TRANSFER_FRAUD',
    ],
    safe_allow_auth_pass_required: true,
  };

  static evaluate(aiResult, userPolicy = {}) {
    const policy = { ...this.DEFAULT_POLICY, ...userPolicy };
    const { risk_score, confidence, primary_category, evidence, recommended_action } = aiResult;

    const catId = primary_category ? primary_category.id : null;
    const isThreatCategory = catId && catId !== 'SAFE';

    // 1. Check for High-Severity / Critical Threat Auto-Quarantine
    const isAutoQuarantineCat = catId && policy.auto_quarantine_categories.includes(catId);
    if (
      (risk_score >= policy.quarantine_risk_threshold && confidence >= policy.quarantine_min_confidence) ||
      (isAutoQuarantineCat && risk_score >= 60)
    ) {
      return {
        policy_decision: 'QUARANTINE',
        allowed_action: true,
        action_type: 'QUARANTINE',
        reason: `Risk score (${risk_score}/100) and confidence (${Math.round(confidence * 100)}%) satisfy quarantine policy criteria for category "${primary_category?.name || 'High Risk Threat'}".`,
        requires_user_override: false,
        audit_trail: {
          evaluated_score: risk_score,
          threshold: policy.quarantine_risk_threshold,
          confidence,
          category: catId,
        },
      };
    }

    // 2. Check for Spam / Low-level abuse
    if (catId === 'SPAM' || catId === 'BULK_EMAIL' || (risk_score >= policy.spam_risk_threshold && risk_score < policy.quarantine_risk_threshold)) {
      return {
        policy_decision: 'SPAM',
        allowed_action: true,
        action_type: 'SPAM',
        reason: `Email evaluated as unsolicited/spam content (Risk: ${risk_score}/100). Policy directs routing to Spam.`,
        requires_user_override: false,
        audit_trail: {
          evaluated_score: risk_score,
          threshold: policy.spam_risk_threshold,
          category: catId,
        },
      };
    }

    // 3. Suspicious / Warning
    if (risk_score >= 25 || catId === 'UNKNOWN_SUSPICIOUS') {
      return {
        policy_decision: 'FLAG',
        allowed_action: true,
        action_type: 'FLAG',
        reason: `Suspicious characteristics detected (Risk: ${risk_score}/100). In-place warning banner active.`,
        requires_user_override: false,
        audit_trail: {
          evaluated_score: risk_score,
          category: catId,
        },
      };
    }

    // 4. Safe email
    return {
      policy_decision: 'ALLOW',
      allowed_action: true,
      action_type: 'ALLOW',
      reason: 'No policy violations detected. Email permitted in inbox with safety indicator.',
      requires_user_override: false,
      audit_trail: {
        evaluated_score: risk_score,
        category: 'SAFE',
      },
    };
  }
}
