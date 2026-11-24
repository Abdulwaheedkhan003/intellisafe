// ============================================================
// COMPREHENSIVE TEST SUITE — ThreatLens AI Security Pipeline
// ============================================================

import assert from 'assert';
import { THREAT_TAXONOMY } from '../backend/taxonomy.js';
import { SenderDetector } from '../backend/detectors/sender_detector.js';
import { HeaderDetector } from '../backend/detectors/header_detector.js';
import { UrlDetector } from '../backend/detectors/url_detector.js';
import { ContentDetector } from '../backend/detectors/content_detector.js';
import { AttachmentDetector } from '../backend/detectors/attachment_detector.js';
import { EmailSecurityInvestigationAgent } from '../backend/agent/investigation_agent.js';
import { RiskEngine } from '../backend/engine/risk_engine.js';
import { ExplanationEngine } from '../backend/engine/explanation_engine.js';
import { PolicyEngine } from '../backend/engine/policy_engine.js';
import { ActionExecutor } from '../backend/actions/action_executor.js';
import { DemoMailboxService } from '../backend/services/demo_mailbox_service.js';
import { SAMPLE_EMAILS } from '../backend/data/sample_emails.js';
import { NormalizedEmail } from '../backend/schemas/email_schema.js';

let passed = 0;
let total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    Error: ${err.message}`);
  }
}

async function asyncTest(name, fn) {
  total++;
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    Error: ${err.message}`);
  }
}

console.log('\n=======================================================');
console.log('  🧪 Running ThreatLens AI Architecture Verification');
console.log('=======================================================\n');

// ── 1. Taxonomy Tests ─────────────────────────────────────────
console.log('--- Phase 1: Threat Taxonomy Verification ---');
test('Taxonomy contains 105+ categories and parent groups', () => {
  const catCount = Object.keys(THREAT_TAXONOMY.CATEGORIES).length;
  assert(catCount >= 105, `Expected >= 105 categories, got ${catCount}`);
  assert(Object.keys(THREAT_TAXONOMY.PARENTS).length >= 8, 'Expected parent taxonomy groups');
  assert(THREAT_TAXONOMY.CATEGORIES.PHISHING, 'PHISHING category exists');
  assert(THREAT_TAXONOMY.CATEGORIES.BEC, 'BEC category exists');
  assert(THREAT_TAXONOMY.CATEGORIES.CREDENTIAL_HARVESTING, 'CREDENTIAL_HARVESTING exists');
});

// ── 2. Detector Tests ─────────────────────────────────────────
console.log('\n--- Phase 2: Deterministic Fast Detectors ---');
test('SenderDetector catches brand impersonation & typosquatting', () => {
  const fakeMsft = new NormalizedEmail({
    from_name: 'Microsoft Account Team',
    from_email: 'alerts@micros0ft-security.com',
  });
  const evidence = SenderDetector.analyze(fakeMsft);
  const brandImp = evidence.find(e => e.signal === 'brand_impersonation');
  const typo = evidence.find(e => e.signal === 'typosquatting');
  assert(brandImp, 'Brand impersonation detected');
  assert(typo, 'Typosquatting detected');
  assert(brandImp.verified === true, 'Evidence is marked verified');
});

test('HeaderDetector detects SPF & DKIM failures', () => {
  const badAuth = new NormalizedEmail({
    spf: 'FAIL',
    dkim: 'FAIL',
    dmarc: 'FAIL',
  });
  const evidence = HeaderDetector.analyze(badAuth);
  assert(evidence.some(e => e.signal === 'spf_fail'), 'SPF fail detected');
  assert(evidence.some(e => e.signal === 'dkim_fail'), 'DKIM fail detected');
  assert(evidence.some(e => e.signal === 'dmarc_fail'), 'DMARC fail detected');
});

test('UrlDetector detects fake login paths and raw IP hosts', () => {
  const badUrls = new NormalizedEmail({
    urls: ['http://192.168.1.100/patch.exe', 'https://secure-login-portal.xyz/auth/login.php'],
  });
  const evidence = UrlDetector.analyze(badUrls);
  assert(evidence.some(e => e.signal === 'ip_address_url'), 'IP URL detected');
  assert(evidence.some(e => e.signal === 'fake_login_url'), 'Fake login page detected');
});

test('ContentDetector detects urgency, credentials, and bank account changes', () => {
  const becText = new NormalizedEmail({
    subject: 'Urgent Wire Transfer Needed',
    body_text: 'Please find our updated new bank account details instructions. Action required within 2 hours.',
  });
  const evidence = ContentDetector.analyze(becText);
  assert(evidence.some(e => e.signal === 'urgency_language'), 'Urgency detected');
  assert(evidence.some(e => e.signal === 'new_bank_account'), 'New bank account detected');
});

test('AttachmentDetector detects executables and macro-enabled documents', () => {
  const evilAtt = new NormalizedEmail({
    attachments: [
      { name: 'payload.exe', size: 50000 },
      { name: 'Invoice.xlsm', size: 120000 },
    ],
  });
  const evidence = AttachmentDetector.analyze(evilAtt);
  assert(evidence.some(e => e.signal === 'executable_attachment'), 'Executable attachment detected');
  assert(evidence.some(e => e.signal === 'macro_enabled_document'), 'Macro document detected');
});

// ── 3. Agentic AI Investigator Tests ──────────────────────────
console.log('\n--- Phase 3: EmailSecurityInvestigationAgent Workflow ---');
await asyncTest('Agent performs reasoned multi-tool investigation and generates timeline', async () => {
  const agent = new EmailSecurityInvestigationAgent();
  const phishingSample = SAMPLE_EMAILS.find(s => s.expected_category === 'PHISHING');
  assert(phishingSample, 'Phishing sample found');

  const email = new NormalizedEmail(phishingSample);
  const result = await agent.investigate(email);

  assert(result.is_threat === true, 'Phishing classified as threat');
  assert(result.risk_score >= 80, `Risk score >= 80 (got ${result.risk_score})`);
  assert(result.confidence >= 0.85, 'High confidence');
  assert(result.investigation_timeline.length >= 8, 'Timeline contains actual investigation steps');
  assert(result.explanation.includes('phishing') || result.explanation.includes('Microsoft') || result.explanation.includes('credential'), 'Dynamic explanation references actual evidence');
});

// ── 4. Policy Engine & Separation of Control ──────────────────
console.log('\n--- Phase 4: Policy Engine & Action Authorization ---');
test('PolicyEngine routes high-risk threat to QUARANTINE and safe to ALLOW', () => {
  const highRiskResult = {
    risk_score: 94,
    confidence: 0.96,
    primary_category: { id: 'PHISHING', name: 'Phishing', severity: 'CRITICAL' },
    evidence: [],
    recommended_action: 'QUARANTINE',
  };
  const decision = PolicyEngine.evaluate(highRiskResult);
  assert.strictEqual(decision.policy_decision, 'QUARANTINE', 'High risk triggers quarantine');
  assert(decision.allowed_action === true, 'Action is authorized');

  const safeResult = {
    risk_score: 5,
    confidence: 0.98,
    primary_category: null,
    evidence: [],
    recommended_action: 'ALLOW',
  };
  const safeDecision = PolicyEngine.evaluate(safeResult);
  assert.strictEqual(safeDecision.policy_decision, 'ALLOW', 'Clean email triggers allow');
});

// ── 5. Action Executor & Restoration Lifecycle ────────────────
console.log('\n--- Phase 5: Action Executor & Quarantine Restoration ---');
await asyncTest('ActionExecutor stores quarantine item and restores back to Inbox', async () => {
  const mailbox = new DemoMailboxService();
  const executor = new ActionExecutor(mailbox, null);

  const testEmail = new NormalizedEmail({ id: 'test_msg_999', subject: 'Threat Email' });
  const testInv = { risk_score: 95, primary_category: { name: 'Phishing' }, recommended_action: 'QUARANTINE' };
  const policyDec = { policy_decision: 'QUARANTINE', reason: 'High risk' };

  // 1. Execute Quarantine
  const execRes = await executor.execute({
    email: testEmail,
    investigation: testInv,
    policyDecision: policyDec,
    isLive: false,
  });
  assert(execRes.quarantined === true, 'Quarantine executed');
  assert(executor.getQuarantinedItems().length === 1, 'Quarantine store contains 1 item');
  assert(executor.getAuditLog().length === 1, 'Audit log recorded 1 action');

  // 2. Execute Restore
  const restoreRes = await executor.restoreFromQuarantine('test_msg_999', false);
  assert(restoreRes.success === true, 'Restoration succeeded');
  assert(executor.getAuditLog().length === 2, 'Audit log recorded restore event');
});

// ── 6. All 10 Sample Threats Verification ─────────────────────
console.log('\n--- Phase 6: All 10 Distinct Threat Samples Verification ---');
for (const sample of SAMPLE_EMAILS) {
  await asyncTest(`Sample test: [${sample.expected_category}] - "${sample.subject.slice(0, 35)}…"`, async () => {
    const agent = new EmailSecurityInvestigationAgent();
    const email = new NormalizedEmail(sample);
    const result = await agent.investigate(email);

    if (sample.expected_category === 'SAFE') {
      assert(result.is_threat === false, 'Safe email is NOT flagged as threat');
      assert(result.risk_score < 25, `Risk score is low (got ${result.risk_score})`);
      assert(result.explanation.includes('no significant') || result.explanation.includes('evidence'), 'Safe explanation generated');
    } else {
      assert(result.is_threat === true, `Threat flagged for ${sample.expected_category}`);
      assert(result.risk_score >= 35, `Risk score >= 35 (got ${result.risk_score})`);
      assert(result.primary_category !== null, 'Primary category assigned');
      assert(result.evidence.some(e => e.verified), 'Verified evidence present');
    }
  });
}

console.log('\n=======================================================');
console.log(`  📊 Test Results: ${passed} / ${total} Passed (${Math.round((passed / total) * 100)}%)`);
console.log('=======================================================\n');

if (passed !== total) {
  process.exit(1);
}
