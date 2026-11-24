// ============================================================
// CONTENT SCRIPT — Gmail DOM Integration (ThreatLens)
// Monitors Gmail for email opens, extracts DOM payload,
// communicates with ThreatLens Backend Security Engine,
// and injects the explainable threat card.
// ============================================================

(function () {
  'use strict';

  let lastProcessedMessageId = null;
  let analysisInProgress = false;
  let currentRoot = null;
  const BACKEND_URL = 'http://localhost:3000';

  const SELECTORS = {
    emailContainer: [
      '[data-message-id]',
      '.a3s.aiL',
      '[role="main"] .nH.if.adk',
    ],
    subject: [
      'h2.hP',
      '[data-legacy-message-id] h2',
      '.ha .hP',
    ],
    from: [
      '.gD[email]',
      '.go[email]',
      'span[email]',
    ],
    body: [
      '.a3s.aiL',
      '.a3s',
      '[role="presentation"] .a3s',
    ],
    messageMain: [
      '[role="main"]',
      '#MailViewer',
    ],
    attachments: [
      '.aZo',
      '.aQH span[download]',
    ],
  };

  function init() {
    console.log('[ThreatLens] Content script active on Gmail');

    const observer = new MutationObserver(debounce(onDomChange, 500));
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
    });

    onDomChange();
  }

  function onDomChange() {
    const emailView = findEmailView();
    if (!emailView) return;

    const messageId = getMessageId(emailView);
    if (messageId && messageId === lastProcessedMessageId) return;
    if (analysisInProgress) return;

    lastProcessedMessageId = messageId;
    processEmail(emailView, messageId);
  }

  function findEmailView() {
    for (const selector of SELECTORS.messageMain) {
      const main = document.querySelector(selector);
      if (main) {
        const emailEl = main.querySelector('[data-message-id]') ||
                        main.querySelector('.a3s.aiL') ||
                        main.querySelector('.nH.if');
        if (emailEl) return emailEl;
      }
    }
    return null;
  }

  function getMessageId(el) {
    return el.getAttribute('data-message-id') ||
           el.closest('[data-message-id]')?.getAttribute('data-message-id') ||
           el.innerHTML.length.toString();
  }

  function extractEmailData(emailView, messageId) {
    const doc = document;

    let subject = '';
    for (const sel of SELECTORS.subject) {
      const el = doc.querySelector(sel);
      if (el && el.textContent.trim()) { subject = el.textContent.trim(); break; }
    }

    let from_name = '';
    let from_email = '';
    for (const sel of SELECTORS.from) {
      const el = doc.querySelector(sel);
      if (el) {
        from_name = el.textContent.trim();
        from_email = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || '';
        break;
      }
    }

    let html_body = '';
    let text_body = '';
    for (const sel of SELECTORS.body) {
      const el = doc.querySelector(sel);
      if (el && el.innerHTML.trim().length > 20) {
        html_body = el.innerHTML;
        text_body = el.textContent;
        break;
      }
    }

    const raw_headers = buildHeadersFromDOM(doc);
    const attachments = extractAttachments(doc);

    return {
      id: messageId,
      subject,
      from_name,
      from_email,
      from_raw: `${from_name} <${from_email}>`,
      html_body,
      body_html: html_body,
      text_body,
      body_text: text_body,
      raw_headers,
      attachments,
      headers: {},
    };
  }

  function buildHeadersFromDOM(doc) {
    let headers = '';
    const authInfo = doc.querySelector('.adn.ads');
    if (authInfo) {
      const text = authInfo.textContent;
      if (/spf=pass/i.test(text)) headers += 'Authentication-Results: spf=pass\n';
      if (/spf=fail/i.test(text)) headers += 'Authentication-Results: spf=fail\n';
      if (/dkim=pass/i.test(text)) headers += 'Authentication-Results: dkim=pass\n';
      if (/dkim=fail/i.test(text)) headers += 'Authentication-Results: dkim=fail\n';
      if (/dmarc=pass/i.test(text)) headers += 'Authentication-Results: dmarc=pass\n';
      if (/dmarc=fail/i.test(text)) headers += 'Authentication-Results: dmarc=fail\n';
    }
    const replyToEl = doc.querySelector('.adn [data-tooltip="Reply-To"] span, [title="Reply-To"] + span');
    if (replyToEl) {
      headers += `Reply-To: ${replyToEl.textContent.trim()}\n`;
    }
    return headers;
  }

  function extractAttachments(doc) {
    const attachments = [];
    const attachEls = doc.querySelectorAll('.aZo, .aQH span[download], [data-tooltip*="Download"]');
    attachEls.forEach(el => {
      const name = el.getAttribute('download') ||
                   el.getAttribute('data-tooltip') ||
                   el.textContent.trim();
      if (name) {
        attachments.push({ name, size: 0, mimeType: '' });
      }
    });
    return attachments;
  }

  async function processEmail(emailView, messageId) {
    analysisInProgress = true;

    try {
      removeExistingCard();

      const injectionPoint = findInjectionPoint();
      if (!injectionPoint) {
        analysisInProgress = false;
        return;
      }

      const rootDiv = document.createElement('div');
      rootDiv.id = 'threatlens-root';
      const loadingCard = ThreatCard.renderLoading();
      rootDiv.appendChild(loadingCard);
      injectionPoint.insertBefore(rootDiv, injectionPoint.firstChild);
      currentRoot = rootDiv;

      const emailData = extractEmailData(emailView, messageId);

      let result = null;

      // 1. Try Backend API First (Agentic AI + Risk + Policy)
      try {
        const response = await fetch(`${BACKEND_URL}/api/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(emailData),
        });
        if (response.ok) {
          const json = await response.json();
          result = json.result;
        }
      } catch (backendErr) {
        console.log('[ThreatLens] Backend API unreachable, falling back to local analysis');
      }

      // 2. Local Fallback if backend offline
      if (!result && typeof AnalysisEngine !== 'undefined') {
        result = await AnalysisEngine.analyze(emailData);
      }

      if (result) {
        rootDiv.innerHTML = '';
        const card = ThreatCard.render(result);
        rootDiv.appendChild(card);

        // Notify background worker
        if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
          chrome.runtime.sendMessage({
            type: 'ANALYSIS_COMPLETE',
            risk_score: result.risk_score,
            category: result.primary_category?.name,
          });
        }
      }
    } catch (err) {
      console.error('[ThreatLens] Processing error:', err);
      removeExistingCard();
    } finally {
      analysisInProgress = false;
    }
  }

  function findInjectionPoint() {
    const candidates = [
      document.querySelector('[role="main"] .nH.bkL'),
      document.querySelector('[role="main"] .kN.I5.J-J5-Ji'),
      document.querySelector('[role="main"] > div > div'),
      document.querySelector('[role="main"] .aeF'),
      document.querySelector('[role="main"]'),
    ];
    return candidates.find(Boolean) || null;
  }

  function removeExistingCard() {
    const existing = document.getElementById('threatlens-root');
    if (existing) existing.remove();
    currentRoot = null;
    const fp = document.getElementById('threatlens-forensic-overlay');
    if (fp) fp.remove();
  }

  function debounce(fn, delay) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
