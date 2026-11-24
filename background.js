// ============================================================
// BACKGROUND SERVICE WORKER — ThreatLens
// Maintains connection to backend security engine, synchronizes
// 24/7 monitoring status, and updates icon badges.
// ============================================================

const BACKEND_URL = 'http://localhost:3000';

chrome.runtime.onInstalled.addListener(() => {
  console.log('[ThreatLens] Background Service Worker installed');
  chrome.storage.local.set({
    threatlens_enabled: true,
    backend_status: 'ONLINE',
    quarantine_count: 0,
    last_sync: new Date().toISOString(),
  });
  syncBackendStatus();
});

// Periodic status sync
chrome.alarms?.create('sync_status', { periodInMinutes: 1 });
chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name === 'sync_status') {
    syncBackendStatus();
  }
});

async function syncBackendStatus() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/status`);
    if (res.ok) {
      const data = await res.json();
      chrome.storage.local.set({
        backend_status: 'ONLINE',
        monitoring: data.monitoring,
        quarantine_count: data.quarantine_count || 0,
        last_sync: new Date().toISOString(),
      });
    }
  } catch (err) {
    chrome.storage.local.set({ backend_status: 'OFFLINE_FALLBACK' });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYSIS_COMPLETE') {
    const score = message.risk_score || 0;
    const tabId = sender.tab && sender.tab.id;
    if (tabId) {
      updateBadge(tabId, score);
    }
    syncBackendStatus();
    sendResponse({ ok: true });
  } else if (message.type === 'GET_STATUS') {
    chrome.storage.local.get(null, (data) => {
      sendResponse(data);
    });
    return true;
  }
  return true;
});

function updateBadge(tabId, score) {
  let text = '';
  let color = '#636366';

  if (score >= 80) { text = '!'; color = '#FF2D55'; }
  else if (score >= 60) { text = '!'; color = '#FF6B35'; }
  else if (score >= 35) { text = '?'; color = '#FFD60A'; }
  else { text = '✓'; color = '#34C759'; }

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}
