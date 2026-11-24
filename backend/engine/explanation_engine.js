// ============================================================
// EXPLANATION ENGINE — Backend Module
// Generates concise, dynamic, evidence-grounded explanations.
// Strict No-Fabrication Protocol: References ONLY verified evidence.
// ============================================================

export class ExplanationEngine {
  static formatWhyExplanation(primaryCategory, verifiedEvidence, emailData) {
    if (!primaryCategory || primaryCategory.id === 'SAFE') {
      return 'Based on the available evidence, no significant phishing, spoofing, malware, or social-engineering indicators were detected.';
    }

    if (primaryCategory.id === 'UNKNOWN_SUSPICIOUS') {
      return 'The system detected unusual characteristics but does not have enough verified evidence to confidently assign a specific threat category.';
    }

    const reasons = [];

    // 1. Sender evidence
    const brandImp = verifiedEvidence.find(e => e.signal === 'brand_impersonation');
    const domainMismatch = verifiedEvidence.find(e => e.signal === 'domain_mismatch');
    const typo = verifiedEvidence.find(e => e.signal === 'typosquatting');
    const replyMismatch = verifiedEvidence.find(e => e.signal === 'reply_to_mismatch');
    const execImp = verifiedEvidence.find(e => e.signal === 'executive_impersonation');

    if (brandImp && brandImp.value) {
      reasons.push(`claims to represent ${brandImp.value.brand}, but originates from "${brandImp.value.actualDomain}" rather than legitimate channels`);
    } else if (typo && typo.value) {
      reasons.push(`originates from a lookalike domain ("${typo.value.senderDomain}") mimicking "${typo.value.targetDomain}"`);
    } else if (execImp) {
      reasons.push(`claims executive authority in display name from an external free email provider`);
    } else if (domainMismatch) {
      reasons.push(`the sender domain does not match the claimed identity`);
    }

    if (replyMismatch && replyMismatch.value) {
      reasons.push(`diverts replies to an external address (${replyMismatch.value.replyTo})`);
    }

    // 2. URL evidence
    const fakeLogin = verifiedEvidence.find(e => e.signal === 'fake_login_url');
    const ipUrl = verifiedEvidence.find(e => e.signal === 'ip_address_url');
    const shortUrl = verifiedEvidence.find(e => e.signal === 'url_shortener');

    if (fakeLogin) {
      reasons.push('directs the recipient to a deceptive login verification webpage');
    } else if (ipUrl) {
      reasons.push('contains a raw IP-based web link bypassing standard domain name infrastructure');
    } else if (shortUrl) {
      reasons.push('uses a URL shortener to conceal the true web destination');
    }

    // 3. Content evidence
    const credReq = verifiedEvidence.find(e => e.signal === 'credential_request');
    const urgency = verifiedEvidence.find(e => e.signal === 'urgency_language');
    const suspThreat = verifiedEvidence.find(e => e.signal === 'account_suspension_threat');
    const newBank = verifiedEvidence.find(e => e.signal === 'new_bank_account');
    const wireReq = verifiedEvidence.find(e => e.signal === 'wire_transfer_request');
    const secrecy = verifiedEvidence.find(e => e.signal === 'secrecy_request');
    const extortion = verifiedEvidence.find(e => e.signal === 'extortion_keywords');
    const harassment = verifiedEvidence.find(e => e.signal === 'harassment_keywords');
    const investment = verifiedEvidence.find(e => e.signal === 'investment_offer');
    const prize = verifiedEvidence.find(e => e.signal === 'prize_claim');

    if (credReq && urgency) {
      reasons.push('urgently requests password or account verification to avert simulated deadlines');
    } else if (credReq) {
      reasons.push('asks the recipient to submit sensitive login credentials');
    }

    if (suspThreat) {
      reasons.push('threatens immediate account suspension if credentials are not promptly validated');
    }

    if (newBank || wireReq) {
      reasons.push('solicits wire transfer payment to altered banking coordinates');
    }

    if (secrecy) {
      reasons.push('instructs the recipient to bypass normal internal verification procedures');
    }

    if (extortion) {
      reasons.push('uses blackmail threats demanding cryptocurrency payment');
    }

    if (harassment) {
      reasons.push('contains threatening and abusive language');
    }

    if (investment) {
      reasons.push('promises unrealistic guaranteed investment returns');
    }

    if (prize) {
      reasons.push('claims unverified lottery or prize winnings requiring advance fees');
    }

    // 4. Attachment evidence
    const execAtt = verifiedEvidence.find(e => e.signal === 'executable_attachment');
    const macroAtt = verifiedEvidence.find(e => e.signal === 'macro_enabled_document');
    const scriptAtt = verifiedEvidence.find(e => e.signal === 'script_attachment');
    const htmlAtt = verifiedEvidence.find(e => e.signal === 'html_attachment');

    if (execAtt && execAtt.value) {
      reasons.push(`delivers a high-risk executable file (${execAtt.value.filename})`);
    } else if (macroAtt && macroAtt.value) {
      reasons.push(`contains a macro-enabled Office file (${macroAtt.value.filename}) capable of executing code`);
    } else if (scriptAtt && scriptAtt.value) {
      reasons.push(`attaches a script file (${scriptAtt.value.filename})`);
    } else if (htmlAtt && htmlAtt.value) {
      reasons.push(`includes an HTML file (${htmlAtt.value.filename}) presenting an offline phishing risk`);
    }

    if (reasons.length === 0) {
      return `This email is classified as ${primaryCategory.name} due to correlated forensic indicators detected during inspection.`;
    }

    return `This email appears to be a ${primaryCategory.name} attempt because it ${reasons.slice(0, 3).join(', and ')}.`;
  }

  static formatVerifiedEvidenceList(evidenceList) {
    return evidenceList
      .filter(e => e.verified)
      .map(e => ({
        type: e.type,
        finding: e.finding,
        value: e.value,
        severity: e.severity,
        status: e.verification_status,
        confidence_pct: Math.round(e.confidence * 100),
      }));
  }
}
