// ============================================================
// EMAIL SECURITY INVESTIGATION AGENT
// Agentic AI Security Analyst Workflow
// Reasoned, multi-tool investigation of email threats
// ============================================================

import { AgentTools } from './tools.js';

export class EmailSecurityInvestigationAgent {
  constructor() {
    this.name = 'EmailSecurityInvestigationAgent';
  }

  async investigate(emailData, fastEvidence = []) {
    const timeline = [];
    const recordStep = (action, details) => {
      timeline.push({
        time: new Date().toISOString(),
        action,
        details,
      });
    };

    recordStep('INVESTIGATION_INITIATED', `Email received from "${emailData.from_email || emailData.from_raw}" with subject "${emailData.subject}"`);

    const tools = new AgentTools(emailData, fastEvidence);

    // ── Phase 1: Sender & Authentication Investigation ──────────
    recordStep('TOOL_EXECUTION: analyze_sender', 'Examining sender display name, envelope address, and domain validity');
    const senderRes = tools.analyze_sender();
    if (senderRes.evidence.some(e => e.severity === 'CRITICAL' || e.severity === 'HIGH')) {
      recordStep('SIGNAL_DISCOVERY', `High-risk sender anomalies detected: ${senderRes.evidence.map(e => e.signal).join(', ')}`);
    }

    recordStep('TOOL_EXECUTION: analyze_headers', 'Inspecting raw mail headers, SPF/DKIM/DMARC alignment');
    tools.analyze_headers();

    recordStep('TOOL_EXECUTION: analyze_authentication', 'Verifying cryptographic message authentication records');
    const authRes = tools.analyze_authentication();
    if (authRes.has_auth_failures) {
      recordStep('AUTH_FAILURE', 'Domain authentication failed (SPF/DKIM/DMARC mismatch)');
    } else if (authRes.all_passed) {
      recordStep('AUTH_PASSED', 'Cryptographic sender authentication verified (SPF & DKIM pass)');
    }

    // ── Phase 2: URL & Domain Infrastructure Analysis ───────────
    if (emailData.urls && emailData.urls.length > 0) {
      recordStep('TOOL_EXECUTION: extract_urls', `Extracted ${emailData.urls.length} destination link(s) from email payload`);
      tools.extract_urls();

      recordStep('TOOL_EXECUTION: inspect_urls', 'Scanning URLs for phishing paths, raw IP hosts, and obfuscation');
      const urlRes = tools.inspect_urls();

      recordStep('TOOL_EXECUTION: analyze_domains', 'Evaluating target domains and lookalike patterns');
      tools.analyze_domains();

      recordStep('TOOL_EXECUTION: analyze_ip_addresses', 'Checking for unresolvable raw IP addresses in links');
      tools.analyze_ip_addresses();
    } else {
      recordStep('URL_CHECK', 'No active hyperlinks found in message body');
    }

    // ── Phase 3: Content & Social Engineering Analysis ──────────
    recordStep('TOOL_EXECUTION: analyze_content', 'Scanning message body for urgency, credential solicitations, and fraud patterns');
    tools.analyze_content();

    recordStep('TOOL_EXECUTION: detect_social_engineering', 'Analyzing psychological pressure tactics (urgency, secrecy, authority coercion)');
    const socEng = tools.detect_social_engineering();
    if (socEng.detected) {
      recordStep('SOCIAL_ENGINEERING_DETECTED', `Tactics found: ${socEng.signals.join(', ')}`);
    }

    recordStep('TOOL_EXECUTION: detect_impersonation', 'Analyzing brand, executive, and organizational impersonation indicators');
    tools.detect_impersonation();

    // ── Phase 4: Attachment Inspection ──────────────────────────
    if (emailData.attachments && emailData.attachments.length > 0) {
      recordStep('TOOL_EXECUTION: analyze_attachments', `Inspecting ${emailData.attachments.length} attachment(s) for executable & macro risks`);
      tools.analyze_attachments();
    }

    // ── Phase 5: Threat Intelligence Verification ───────────────
    recordStep('TOOL_EXECUTION: check_threat_intelligence', 'Cross-referencing IOCs against verified security intelligence');
    const intelRes = tools.check_threat_intelligence();
    if (intelRes.status === 'CONFIRMED_MATCH') {
      recordStep('INTEL_CONFIRMED', `Confirmed threat intelligence match found`);
    } else {
      recordStep('INTEL_STATUS', 'INTELLIGENCE UNAVAILABLE — No external IOC hits; relying on behavioral & structural proof');
    }

    // ── Phase 6: Evidence Correlation & Synthesis ───────────────
    recordStep('TOOL_EXECUTION: correlate_evidence', 'Synthesizing multi-vector signals and removing redundant evidence');
    const corrRes = tools.correlate_evidence();
    recordStep('EVIDENCE_CORRELATED', `${corrRes.total_evidence_items} total verified evidence items synthesized`);

    // ── Phase 7: Threat Classification ──────────────────────────
    recordStep('TOOL_EXECUTION: classify_threat', 'Scoring signals against 105+ Threat Taxonomy categories');
    const classification = tools.classify_threat();

    // ── Phase 8: Confidence & Risk Calculation ──────────────────
    recordStep('TOOL_EXECUTION: calculate_confidence', 'Computing analytic confidence score from verified evidence');
    const confidence = tools.calculate_confidence(tools.collectedEvidence);

    // Compute composite risk score
    const riskScore = this._computeRiskScore(tools.collectedEvidence, classification.primary_category);

    // ── Phase 9: Dynamic Explanation Generation ─────────────────
    recordStep('TOOL_EXECUTION: generate_explanation', 'Formulating concise, evidence-grounded human-readable explanation');
    const explanation = tools.generate_explanation(classification.primary_category, tools.collectedEvidence);

    // ── Phase 10: Recommended Action ────────────────────────────
    recordStep('TOOL_EXECUTION: recommend_action', 'Formulating recommended response action based on risk threshold');
    const recommendedAction = tools.recommend_action(riskScore, classification.primary_category);
    recordStep('INVESTIGATION_CONCLUDED', `Classification: ${classification.primary_category ? classification.primary_category.name : 'SAFE'} · Risk: ${riskScore}/100 · Action: ${recommendedAction}`);

    return {
      is_threat: classification.is_threat && riskScore >= 25,
      primary_category: classification.primary_category,
      secondary_categories: classification.secondary_categories,
      risk_score: riskScore,
      confidence: confidence,
      explanation: explanation,
      evidence: tools.collectedEvidence,
      recommended_action: recommendedAction,
      investigation_timeline: timeline,
      intel_status: intelRes.status === 'CONFIRMED_MATCH' ? 'CONFIRMED' : 'INTELLIGENCE UNAVAILABLE',
    };
  }

  _computeRiskScore(evidenceList, primaryCategory) {
    const verified = evidenceList.filter(e => e.verified && e.severity !== 'SAFE');
    if (verified.length === 0) {
      return 5; // Clean baseline
    }

    let score = 0;
    const weights = {
      'CRITICAL': 35,
      'HIGH': 22,
      'MEDIUM': 12,
      'LOW': 5,
      'INFO': 2,
    };

    for (const item of verified) {
      score += (weights[item.severity] || 5);
    }

    // Boost if multiple threat vectors combine (e.g. sender mismatch + fake url + urgency)
    const types = new Set(verified.map(e => e.type));
    if (types.size >= 3) {
      score += 15;
    } else if (types.size >= 2) {
      score += 8;
    }

    if (primaryCategory && primaryCategory.severity === 'CRITICAL') {
      score = Math.max(score, 75);
    }

    return Math.min(100, Math.max(0, Math.round(score)));
  }
}
