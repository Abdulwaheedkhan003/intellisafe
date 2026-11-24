// ============================================================
// SAFE CARD UI COMPONENT
// Minimal stub — ThreatCard handles both safe and threat modes.
// Exported for explicit safe-only renders if needed.
// ============================================================

const SafeCard = {
  render(result) {
    return ThreatCard.render({ ...result, is_threat: false });
  },
};

if (typeof window !== 'undefined') window.SafeCard = SafeCard;
