// ============================================================
// CONTENT DETECTOR — Backend Module
// Analyses subject line and body text for social engineering,
// urgency, financial redirection, credential requests, scam,
// extortion, harassment, and authority pressure cues.
// ============================================================

import { EvidenceItem, EVIDENCE_TYPES, VERIFICATION_STATUS } from '../schemas/evidence_schema.js';

export class ContentDetector {
  static SIGNALS = {
    urgency_language: {
      severity: 'MEDIUM',
      finding: 'High-urgency deadline language detected (pressure tactic to induce rushed action)',
      patterns: [
        /urgent(ly)?/i, /immediately/i, /right away/i, /action required/i,
        /respond (immediately|now|asap)/i, /within \d+ hours?/i, /within \d+ minutes?/i,
        /act now/i, /limited time/i, /expire[sd]? (soon|today|in \d+)/i,
        /account (will be )?(suspended|terminated|closed|deleted)/i,
        /last (chance|warning|notice)/i, /final (notice|warning|reminder)/i,
        /do not (ignore|delay|miss)/i, /time.sensitive/i, /prompt attention/i,
      ],
    },
    credential_request: {
      severity: 'CRITICAL',
      finding: 'Direct request to submit passwords, account credentials, or MFA codes',
      patterns: [
        /enter your (password|credentials|login)/i,
        /confirm your (password|email|details|account)/i,
        /verify (your|account) (password|credentials)/i,
        /click (here|below|the link) to (verify|confirm|reset|update) (your )?(password|account)/i,
        /reset (your )?password/i, /update (your )?payment (info|details|method)/i,
        /provide (your )?credentials/i, /log in to (verify|confirm)/i,
        /sign in to validate/i, /identity verification required/i,
      ],
    },
    account_suspension_threat: {
      severity: 'HIGH',
      finding: 'Threat of immediate account termination or suspension if recipient fails to act',
      patterns: [
        /account (will be |has been )?(suspended|closed|disabled|terminated|blocked|locked)/i,
        /your (account|access) (will |is about to )?(expire|be lost|be removed)/i,
        /failure to (act|respond|verify)/i, /avoid (suspension|termination|account closure)/i,
        /prevent (your )?account (from )?being/i,
      ],
    },
    payment_request: {
      severity: 'HIGH',
      finding: 'Explicit request for electronic payment, invoice settlement, or fund transfer',
      patterns: [
        /wire transfer/i, /send (\$|£|€|USD|GBP|EUR)[\d,]+/i,
        /transfer of funds/i, /initiate (a |the )?payment/i,
        /process (a |the )?payment/i, /pay (the )?(invoice|balance|amount)/i,
        /outstanding (invoice|balance|payment)/i, /overdue (invoice|payment)/i,
        /remit payment/i, /funds transfer/i, /bank transfer/i,
        /direct transfer/i, /payment due/i, /pay now/i,
      ],
    },
    new_bank_account: {
      severity: 'CRITICAL',
      finding: 'Request to update vendor/supplier banking coordinates (classic BEC diversion technique)',
      patterns: [
        /new (bank )?account (details|information|number)/i,
        /change (of |our )?(bank|payment|account) (details|information)/i,
        /updated (bank|payment|account) (details|information)/i,
        /new (payment|bank|routing) (details|info|instructions)/i,
        /please (update|use|note) (the |our )?new (bank|account|payment)/i,
      ],
    },
    gift_card_request: {
      severity: 'HIGH',
      finding: 'Request to purchase gift cards (iTunes, Google Play, Amazon, Steam) as payment method',
      patterns: [
        /gift card[s]?/i, /itunes (card|gift)/i, /google play (card|gift)/i,
        /amazon (gift card|card)/i, /steam card/i,
        /buy (some |[\d]+)? gift card/i, /purchase (a |some )?gift card/i,
        /send (the |a )?gift card (code|number)/i, /redeem (the |a )?gift card/i,
      ],
    },
    secrecy_request: {
      severity: 'HIGH',
      finding: 'Explicit instruction to maintain confidentiality or bypass standard verification protocols',
      patterns: [
        /keep this (strictly )?confidential/i, /do not (mention|tell|discuss|inform)/i,
        /keep this between (us|you and me)/i, /private matter/i,
        /do not call me/i, /i am in a meeting/i, /cannot take calls/i,
        /skip (the |normal )?(process|approval|procedure)/i,
      ],
    },
    extortion_keywords: {
      severity: 'CRITICAL',
      finding: 'Extortion or blackmail language threatening exposure of private material',
      patterns: [
        /i have recorded you/i, /i have access to your (webcam|camera|device|computer)/i,
        /i know your password/i, /compromised your (device|system|account)/i,
        /pay (in |via )?bitcoin/i, /btc address/i, /wallet address/i,
        /or i will (send|release|leak|publish|expose)/i, /ruin your reputation/i,
        /send this to (all )?your contacts/i,
      ],
    },
    harassment_keywords: {
      severity: 'HIGH',
      finding: 'Hostile, abusive, or explicitly threatening personal retaliation language',
      patterns: [
        /you will regret/i, /watch your back/i, /i will find you/i,
        /i will make you pay/i, /you are dead/i, /kill you/i,
        /destroy you/i, /harm you/i, /pay the consequences/i,
      ],
    },
    investment_offer: {
      severity: 'HIGH',
      finding: 'Unrealistic financial investment promises with guaranteed zero-risk high returns',
      patterns: [
        /guaranteed (return|profit|income)/i, /\d{2,}% (profit|return) (in|within) \d+/i,
        /crypto(currency)? investment/i, /bitcoin (mining|trading|investment)/i,
        /double your (money|investment|crypto)/i, /risk.free (investment|opportunity)/i,
        /passive income/i, /financial freedom/i, /make millions/i,
      ],
    },
    prize_claim: {
      severity: 'HIGH',
      finding: 'Unsolicited prize, lottery, or inheritance winnings notification requiring advance fees',
      patterns: [
        /you (have )?won/i, /lottery winner/i, /congratulations.{1,30}winner/i,
        /claim your (prize|reward|winnings|grant)/i, /selected to receive/i,
        /unclaimed (funds|money|inheritance|estate)/i, /beneficiary/i,
      ],
    },
  };

  static analyze(emailData) {
    const evidence = [];
    const textToScan = [
      emailData.subject || '',
      emailData.body_text || '',
      this._stripHtml(emailData.body_html || ''),
    ].join(' ');

    if (!textToScan.trim()) {
      return evidence;
    }

    for (const [signalName, def] of Object.entries(this.SIGNALS)) {
      const match = def.patterns.find(pattern => pattern.test(textToScan));
      if (match) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.CONTENT,
          signal: signalName,
          finding: def.finding,
          value: null,
          source: 'content_detector',
          verified: true,
          confidence: 0.92,
          severity: def.severity,
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    if (evidence.length === 0) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.CONTENT,
        signal: 'content_appears_normal',
        finding: 'Message content scanned — no extortion, urgency pressure, or credential harvesting phrases found',
        value: null,
        source: 'content_detector',
        verified: true,
        confidence: 0.90,
        severity: 'SAFE',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    return evidence;
  }

  static _stripHtml(html) {
    return html.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ');
  }
}
