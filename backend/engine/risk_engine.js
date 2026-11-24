// ============================================================
// RISK ENGINE — Backend Module
// Deterministic Risk Scoring, Confidence Evaluation & Severity Labeling
// ============================================================

export class RiskEngine {
  static SEVERITY_LEVELS = {
    CRITICAL: { label: 'CRITICAL', color: '#FF2D55', score_min: 80 },
    HIGH:     { label: 'HIGH',     color: '#FF6B35', score_min: 60 },
    MEDIUM:   { label: 'MEDIUM',   color: '#FFD60A', score_min: 35 },
    LOW:      { label: 'LOW',      color: '#30D158', score_min: 10 },
    SAFE:     { label: 'SAFE',     color: '#34C759', score_min: 0  },
  };

  static evaluate(riskScore) {
    if (riskScore >= 80) return this.SEVERITY_LEVELS.CRITICAL;
    if (riskScore >= 60) return this.SEVERITY_LEVELS.HIGH;
    if (riskScore >= 35) return this.SEVERITY_LEVELS.MEDIUM;
    if (riskScore >= 10) return this.SEVERITY_LEVELS.LOW;
    return this.SEVERITY_LEVELS.SAFE;
  }

  static getConfidenceLabel(confidence) {
    const pct = Math.round(confidence * 100);
    return `${pct}%`;
  }
}
