// ============================================================
// CONTENT DETECTOR
// Analyses email subject + body for social engineering tactics,
// urgency language, financial keywords, extortion, scam, and
// threat signals.
// ============================================================

const ContentDetector = {

  // ── Keyword signal maps ────────────────────────────────
  SIGNALS: {
    urgency_language: {
      severity: 'MEDIUM',
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
      patterns: [
        /enter your (password|credentials|login)/i,
        /confirm your (password|email|details|account)/i,
        /verify (your|account) (password|credentials)/i,
        /click (here|below|the link) to (verify|confirm|reset|update) (your )?(password|account)/i,
        /reset (your )?password/i, /update (your )?payment (info|details|method)/i,
        /provide (your )?credentials/i, /log in to (verify|confirm)/i,
      ],
    },
    account_suspension_threat: {
      severity: 'HIGH',
      patterns: [
        /account (will be |has been )?(suspended|closed|disabled|terminated|blocked|locked)/i,
        /your (account|access) (will |is about to )?(expire|be lost|be removed)/i,
        /failure to (act|respond|verify)/i, /avoid (suspension|termination|account closure)/i,
        /prevent (your )?account (from )?being/i,
      ],
    },
    payment_request: {
      severity: 'HIGH',
      patterns: [
        /wire transfer/i, /send (\$|£|€|USD|GBP|EUR)[\d,]+/i,
        /transfer of funds/i, /initiate (a |the )?payment/i,
        /process (a |the )?payment/i, /pay (the )?(invoice|balance|amount)/i,
        /outstanding (invoice|balance|payment)/i, /overdue (invoice|payment)/i,
        /remit payment/i, /funds transfer/i, /bank transfer/i,
        /direct transfer/i, /payment due/i, /pay now/i,
      ],
    },
    financial_request: {
      severity: 'HIGH',
      patterns: [
        /financial transaction/i, /authorise (a )?payment/i,
        /approve (this |the )?transfer/i, /banking (details|information)/i,
      ],
    },
    new_bank_account: {
      severity: 'CRITICAL',
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
      patterns: [
        /gift card[s]?/i, /itunes (card|gift)/i, /google play (card|gift)/i,
        /amazon (gift card|card)/i, /steam card/i,
        /buy (some |[\d]+)? gift card/i, /purchase (a |some )?gift card/i,
        /send (the |a )?gift card (code|number)/i, /redeem (the |a )?gift card/i,
      ],
    },
    wire_transfer_request: {
      severity: 'CRITICAL',
      patterns: [
        /wire (transfer|the funds)/i, /initiate (a )?wire/i,
        /swift (transfer|code|payment)/i, /international (transfer|wire)/i,
        /iban.*transfer/i,
      ],
    },
    secrecy_request: {
      severity: 'HIGH',
      patterns: [
        /keep this (confidential|private|secret|between us)/i,
        /do not (tell|inform|mention) (anyone|colleagues|your boss)/i,
        /do not (call|email) (the bank|accounting|finance) (about this)/i,
        /this is (confidential|private|sensitive)/i, /don.t discuss/i,
      ],
    },
    executive_reference: {
      severity: 'MEDIUM',
      patterns: [
        /on behalf of (the )?(ceo|cfo|president|director|executive)/i,
        /CEO (has |would like|requests)/i, /CFO (has |would like|requests)/i,
        /executive (team|management) (has )?asked/i,
        /your (manager|supervisor|boss|director) (has )?(asked|requested|instructed)/i,
      ],
    },
    prize_claim: {
      severity: 'MEDIUM',
      patterns: [
        /you (have |'ve )?(won|been selected|been chosen)/i,
        /congratulations[,!]? you (have |'ve )?(won|been)/i,
        /claim your (prize|reward|winnings)/i,
        /you are (the |a )?winner/i, /lucky winner/i,
        /unclaimed (prize|reward|winnings)/i,
      ],
    },
    lottery_win_claim: {
      severity: 'MEDIUM',
      patterns: [
        /lottery (winner|prize|jackpot)/i, /lotto (win|prize)/i,
        /sweepstakes (win|prize)/i, /powerball/i, /mega millions/i,
      ],
    },
    investment_offer: {
      severity: 'MEDIUM',
      patterns: [
        /guaranteed (returns?|profit|income)/i, /risk.free investment/i,
        /high.yield investment/i, /passive income opportunity/i,
        /double your (money|investment)/i, /triple your (money|investment)/i,
      ],
    },
    unrealistic_returns: {
      severity: 'MEDIUM',
      patterns: [
        /\d{3,}% (return|profit|gain)/i, /earn \$[\d,]+ (per|a) (day|week|month)/i,
        /make (\$|£|€)[\d,]+ (from home|working from home|online)/i,
      ],
    },
    crypto_payment_request: {
      severity: 'HIGH',
      patterns: [
        /bitcoin address/i, /send bitcoin/i, /crypto(currency)? (payment|transfer)/i,
        /pay in (bitcoin|btc|ethereum|eth|usdt|crypto)/i,
        /wallet address/i, /cryptocurrency wallet/i,
        /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/, // Bitcoin address pattern
      ],
    },
    extortion_keywords: {
      severity: 'CRITICAL',
      patterns: [
        /i have (hacked|compromised|access to) your (computer|webcam|camera|account)/i,
        /i recorded you/i, /i have (video|footage|images|photos) of you/i,
        /pay (or|otherwise) (i will|we will) (publish|send|share|expose)/i,
        /within \d+ hours (or|otherwise)/i, /your (private|intimate) (photos|videos|images)/i,
        /sextortion/i, /pay me/i, /send me (bitcoin|crypto|money)/i,
      ],
    },
    blackmail_keywords: {
      severity: 'CRITICAL',
      patterns: [
        /i know (what you|your secret|about you)/i,
        /i will (expose|reveal|publish|tell) (your|about your)/i,
        /unless you (pay|send)/i, /your reputation/i,
        /silence money/i, /keep (this |it )quiet/i,
      ],
    },
    threat_language: {
      severity: 'HIGH',
      patterns: [
        /you (will|are going to) (suffer|regret|pay)/i,
        /we will (attack|destroy|ruin|harm)/i,
        /legal (action|consequences|proceedings) (will be|is being)/i,
        /arrest (warrant|order)/i, /law enforcement (will|has been)/i,
        /your (assets|accounts|property) (will be|are being) (frozen|seized)/i,
      ],
    },
    harassment_keywords: {
      severity: 'MEDIUM',
      patterns: [
        /(you are|you're) (worthless|pathetic|disgusting|stupid)/i,
        /nobody (likes|wants|cares about) you/i,
        /you should (die|kill yourself)/i,
      ],
    },
    tax_authority_impersonation: {
      severity: 'HIGH',
      patterns: [
        /internal revenue service/i, /irs (notice|audit|refund|warning)/i,
        /tax (refund|audit|notice|penalty)/i, /hmrc/i, /tax authority/i,
        /department of (treasury|revenue)/i, /tax (debt|owed|due)/i,
      ],
    },
    government_agency_keyword: {
      severity: 'MEDIUM',
      patterns: [
        /federal bureau of investigation/i, /\bfbi\b/i, /\bdhs\b/i,
        /department of homeland security/i, /interpol/i, /secret service/i,
        /police (department|authority)/i, /court (order|notice|summons)/i,
        /arrest (warrant|notice)/i,
      ],
    },
    bank_keyword: {
      severity: 'MEDIUM',
      patterns: [
        /your bank (account|details)/i, /online banking/i,
        /banking (app|portal|website)/i, /account (balance|statement)/i,
        /debit|credit card (details|number|information)/i,
        /card (verification|security) (code|number)/i,
      ],
    },
    cloud_service_keyword: {
      severity: 'MEDIUM',
      patterns: [
        /microsoft (365|office|teams|sharepoint|onedrive)/i,
        /google (workspace|drive|docs|cloud)/i,
        /dropbox|box\.com|onedrive/i, /shared (document|file|folder)/i,
        /click to (view|access|open) (the |a )?(shared|document|file)/i,
      ],
    },
    sensitive_info_request: {
      severity: 'HIGH',
      patterns: [
        /social security number/i, /ssn/i, /date of birth/i,
        /passport (number|details|information)/i,
        /driver.?s? licen[sc]e/i, /mother.?s? maiden name/i,
        /national insurance/i, /tax identification number/i,
      ],
    },
    payroll_change_request: {
      severity: 'CRITICAL',
      patterns: [
        /change (my |the )?direct deposit/i, /update (my )?(payroll|salary|pay) (account|details|information)/i,
        /new (payroll|salary|pay) (account|details|bank)/i,
        /payroll (change|update|modification)/i,
      ],
    },
    scam_keywords: {
      severity: 'MEDIUM',
      patterns: [
        /nigerian prince/i, /inheritance fund/i, /million (dollars|pounds|euro)/i,
        /you have been selected/i, /kindly assist/i, /transaction fee/i,
        /advance fee/i, /upfront (fee|payment|cost)/i, /handling fee/i,
      ],
    },
    scare_tactic: {
      severity: 'MEDIUM',
      patterns: [
        /virus (detected|found|identified)/i, /your (computer|device|system) (is|has been) (infected|compromised|hacked)/i,
        /malware (detected|found)/i, /your (files|data) (are|have been) (encrypted|compromised)/i,
        /call (our|the|this) support (number|line|team)/i, /toll.free/i,
      ],
    },
  },

  analyze(emailData) {
    const evidence = [];
    const subject = emailData.subject || '';
    const body = (emailData.text_body || '') + ' ' + (emailData.html_body ? emailData.html_body.replace(/<[^>]+>/g, ' ') : '');
    const combined = subject + ' ' + body;

    for (const [signal, config] of Object.entries(this.SIGNALS)) {
      for (const pattern of config.patterns) {
        const match = combined.match(pattern);
        if (match) {
          evidence.push({
            signal,
            finding: this._buildFinding(signal, match[0], subject, body),
            verified: true,
            severity: config.severity,
            matched_text: match[0].substring(0, 100),
          });
          break; // One finding per signal type
        }
      }
    }

    if (evidence.length === 0) {
      evidence.push({
        signal: 'content_appears_normal',
        finding: 'No suspicious content patterns detected in subject or body',
        verified: true,
        severity: 'NONE',
      });
    }

    return evidence;
  },

  _buildFinding(signal, matchedText, subject, body) {
    const truncated = matchedText.trim().substring(0, 80);
    const map = {
      urgency_language: `Urgency language detected: "${truncated}" — designed to pressure the recipient into acting without verification`,
      credential_request: `Credential request detected: "${truncated}" — the email asks the recipient to provide login information`,
      account_suspension_threat: `Account suspension threat: "${truncated}" — creates fear to force immediate action`,
      payment_request: `Payment request detected: "${truncated}"`,
      financial_request: `Financial action requested: "${truncated}"`,
      new_bank_account: `New bank account details requested: "${truncated}" — a hallmark of payment redirection fraud`,
      gift_card_request: `Gift card purchase requested: "${truncated}" — a common untraceable payment demand in social engineering scams`,
      wire_transfer_request: `Wire transfer requested: "${truncated}" — high-value fraud indicator`,
      secrecy_request: `Secrecy/confidentiality requested: "${truncated}" — designed to prevent the recipient from verifying the request`,
      executive_reference: `Reference to executive authority: "${truncated}" — may be impersonating an executive to create pressure`,
      prize_claim: `Prize claim detected: "${truncated}"`,
      lottery_win_claim: `Lottery win claim detected: "${truncated}"`,
      investment_offer: `Fraudulent investment offer detected: "${truncated}"`,
      unrealistic_returns: `Unrealistic financial returns promised: "${truncated}"`,
      crypto_payment_request: `Cryptocurrency payment requested: "${truncated}"`,
      extortion_keywords: `Extortion language detected: "${truncated}"`,
      blackmail_keywords: `Blackmail language detected: "${truncated}"`,
      threat_language: `Threatening language detected: "${truncated}"`,
      harassment_keywords: `Harassment language detected: "${truncated}"`,
      tax_authority_impersonation: `Tax authority impersonation detected: "${truncated}"`,
      government_agency_keyword: `Government agency reference detected: "${truncated}"`,
      bank_keyword: `Banking/financial reference detected: "${truncated}"`,
      cloud_service_keyword: `Cloud service reference detected: "${truncated}"`,
      sensitive_info_request: `Sensitive personal information requested: "${truncated}"`,
      payroll_change_request: `Payroll account change requested: "${truncated}" — payroll diversion fraud indicator`,
      scam_keywords: `Known scam language detected: "${truncated}"`,
      scare_tactic: `Scare tactic detected: "${truncated}"`,
    };
    return map[signal] || `Suspicious content detected (${signal}): "${truncated}"`;
  },
};

if (typeof window !== 'undefined') window.ContentDetector = ContentDetector;
