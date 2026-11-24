// ============================================================
// EVIDENCE SCHEMA & VALIDATOR
// Strict Evidence Contract for ThreatLens AI
// ============================================================

export const EVIDENCE_TYPES = {
  SENDER: 'SENDER',
  HEADER: 'HEADER',
  AUTH: 'AUTH',
  URL: 'URL',
  CONTENT: 'CONTENT',
  ATTACHMENT: 'ATTACHMENT',
  THREAT_INTEL: 'THREAT_INTEL',
  BEHAVIORAL: 'BEHAVIORAL',
};

export const VERIFICATION_STATUS = {
  CONFIRMED: 'CONFIRMED',       // Deterministically verified facts (SPF fail, known spoofing)
  LIKELY: 'LIKELY',             // High confidence heuristic match
  SUSPICIOUS: 'SUSPICIOUS',     // Anomaly detected without conclusive proof
  UNKNOWN: 'UNKNOWN',           // Insufficient context to determine
  UNAVAILABLE: 'UNAVAILABLE',   // External intelligence or check not available
};

export class EvidenceItem {
  constructor({
    type,
    signal,
    finding,
    value = null,
    source,
    verified = true,
    confidence = 1.0,
    severity = 'MEDIUM',
    verification_status = VERIFICATION_STATUS.CONFIRMED,
    details = null,
  }) {
    if (!type || !EVIDENCE_TYPES[type]) {
      throw new Error(`Invalid evidence type: ${type}`);
    }
    if (!finding) {
      throw new Error('Evidence item must have a non-empty finding message.');
    }

    this.type = type;
    this.signal = signal || 'unspecified_signal';
    this.finding = finding;
    this.value = value;
    this.source = source || 'unknown_source';
    this.verified = Boolean(verified);
    this.confidence = Math.max(0, Math.min(1, typeof confidence === 'number' ? confidence : 0.8));
    this.severity = severity || 'MEDIUM';
    this.verification_status = verification_status || (this.verified ? VERIFICATION_STATUS.CONFIRMED : VERIFICATION_STATUS.SUSPICIOUS);
    this.details = details;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      type: this.type,
      signal: this.signal,
      finding: this.finding,
      value: this.value,
      source: this.source,
      verified: this.verified,
      confidence: this.confidence,
      severity: this.severity,
      verification_status: this.verification_status,
      details: this.details,
      timestamp: this.timestamp,
    };
  }
}

export function validateEvidenceCollection(evidenceList) {
  if (!Array.isArray(evidenceList)) return [];
  return evidenceList.map(item => {
    if (item instanceof EvidenceItem) return item;
    return new EvidenceItem(item);
  });
}
