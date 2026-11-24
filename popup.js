// ============================================================
// POPUP LOGIC — ThreatLens Extension
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {
  const statScanned = document.getElementById('stat-scanned');
  const statThreats = document.getElementById('stat-threats');
  const statQuarantine = document.getElementById('stat-quarantine');
  const modeBadge = document.getElementById('mode-badge');
  const statusText = document.getElementById('status-text');

  document.getElementById('btn-open-soc').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:3000' });
  });

  document.getElementById('btn-open-demo').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:3000' });
  });

  try {
    const res = await fetch('http://localhost:3000/api/status');
    if (res.ok) {
      const data = await res.json();
      const stats = data.monitoring?.stats || {};
      statScanned.textContent = stats.total_scanned || 0;
      statThreats.textContent = stats.threats_detected || 0;
      statQuarantine.textContent = data.quarantine_count || 0;

      if (data.gmail_live?.is_authenticated) {
        modeBadge.textContent = 'LIVE GMAIL';
        modeBadge.style.color = '#34C759';
      } else {
        modeBadge.textContent = 'DEMO MODE';
        modeBadge.style.color = '#FF9500';
      }
      statusText.textContent = 'PROTECTION ACTIVE';
    }
  } catch (err) {
    statusText.textContent = 'LOCAL FALLBACK ACTIVE';
  }
});
