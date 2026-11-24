// ============================================================
// THREATLENS AI EMAIL SECURITY BACKEND SERVER
// Complete REST API, 24/7 Background Security Engine,
// Live Gmail Integration & Simulated Demo Mailbox Environment
// ============================================================

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

import { DemoMailboxService } from './backend/services/demo_mailbox_service.js';
import { GmailService } from './backend/services/gmail_service.js';
import { ActionExecutor } from './backend/actions/action_executor.js';
import { MonitoringWorker } from './backend/services/monitoring_worker.js';
import { SAMPLE_EMAILS } from './backend/data/sample_emails.js';
import { THREAT_TAXONOMY } from './backend/taxonomy.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static dashboard
app.use(express.static(path.join(__dirname, 'public')));
app.use('/styles', express.static(path.join(__dirname, 'styles')));
app.use('/src', express.static(path.join(__dirname, 'src')));
app.use('/icons', express.static(path.join(__dirname, 'icons')));

// ── Initialize Backend Core Services ──────────────────────────
const demoMailboxService = new DemoMailboxService();
const gmailService = new GmailService();
const actionExecutor = new ActionExecutor(demoMailboxService, gmailService);
const monitoringWorker = new MonitoringWorker({
  demoMailboxService,
  gmailService,
  actionExecutor,
  pollIntervalMs: 15000,
});

// Start 24/7 background worker
monitoringWorker.start();

// ── API ROUTES ────────────────────────────────────────────────

// 1. Health & Status
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    system: 'ThreatLens AI Email Security Engine',
    version: '1.0.0',
    monitoring: monitoringWorker.getStatus(),
    gmail_live: gmailService.getStatus(),
    quarantine_count: actionExecutor.getQuarantinedItems().length,
  });
});

// 2. Main Email Analysis Endpoint (invoked by Extension or Background worker)
app.post('/api/analyze', async (req, res) => {
  try {
    const emailData = req.body;
    if (!emailData || (!emailData.body_text && !emailData.body && !emailData.subject)) {
      return res.status(400).json({ error: 'Invalid email payload. Subject or Body is required.' });
    }

    const isLive = Boolean(req.body.is_live && gmailService.isAuthenticated());
    const result = await monitoringWorker.processEmail(emailData, isLive);

    res.json({ ok: true, result });
  } catch (err) {
    console.error('[API /analyze] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 3. Taxonomy Info
app.get('/api/taxonomy', (req, res) => {
  res.json({
    total_categories: Object.keys(THREAT_TAXONOMY.CATEGORIES).length,
    parents: THREAT_TAXONOMY.PARENTS,
    categories: THREAT_TAXONOMY.CATEGORIES,
    severity: THREAT_TAXONOMY.SEVERITY,
  });
});

// 4. Investigations List & Details
app.get('/api/investigations', (req, res) => {
  const list = demoMailboxService.getAllInvestigations();
  res.json({ count: list.length, investigations: list });
});

app.get('/api/investigations/:id', (req, res) => {
  const inv = demoMailboxService.getInvestigation(req.params.id);
  if (!inv) return res.status(404).json({ error: 'Investigation not found' });
  res.json(inv);
});

// 5. Quarantine & Restoration
app.get('/api/quarantine', (req, res) => {
  const items = actionExecutor.getQuarantinedItems();
  res.json({ count: items.length, items });
});

app.post('/api/quarantine/restore', async (req, res) => {
  const { email_id, is_live } = req.body;
  if (!email_id) return res.status(400).json({ error: 'email_id is required' });

  const result = await actionExecutor.restoreFromQuarantine(email_id, Boolean(is_live));
  res.json(result);
});

// 6. Audit Trail Log
app.get('/api/audit-log', (req, res) => {
  const logs = actionExecutor.getAuditLog(100);
  res.json({ count: logs.length, audit_log: logs });
});

// 7. Demo Mailbox Management
app.get('/api/demo/samples', (req, res) => {
  res.json({ count: SAMPLE_EMAILS.length, samples: SAMPLE_EMAILS });
});

app.get('/api/demo/mailbox', (req, res) => {
  res.json({
    inbox: demoMailboxService.getFolder('inbox'),
    quarantine: demoMailboxService.getFolder('quarantine'),
    spam: demoMailboxService.getFolder('spam'),
    trash: demoMailboxService.getFolder('trash'),
  });
});

app.post('/api/demo/send-sample', async (req, res) => {
  const { sample_id } = req.body;
  const sample = SAMPLE_EMAILS.find(s => s.id === sample_id);
  if (!sample) return res.status(404).json({ error: 'Sample email not found' });

  // Deep clone and generate fresh id
  const emailCopy = JSON.parse(JSON.stringify(sample));
  emailCopy.id = `demo_${Date.now()}_${sample.id}`;
  emailCopy.date = new Date().toISOString();

  demoMailboxService.injectCustomEmail(emailCopy);
  const result = await monitoringWorker.processEmail(emailCopy, false);

  res.json({ success: true, email: emailCopy, result });
});

app.post('/api/demo/mailbox/reset', (req, res) => {
  const result = demoMailboxService.resetMailbox();
  res.json(result);
});

app.post('/api/demo/mailbox/move', (req, res) => {
  const { email_id, target_folder } = req.body;
  const result = demoMailboxService.moveToFolder(email_id, target_folder);
  res.json(result);
});

// 8. Live Gmail OAuth & Actions
app.get('/api/gmail/status', (req, res) => {
  res.json(gmailService.getStatus());
});

app.get('/api/gmail/auth-url', (req, res) => {
  res.json({ auth_url: gmailService.getAuthUrl() });
});

app.post('/api/gmail/credentials', (req, res) => {
  const { clientId, clientSecret, redirectUri } = req.body;
  gmailService.setCredentials({ clientId, clientSecret, redirectUri });
  res.json({ success: true, status: gmailService.getStatus() });
});

app.get('/api/gmail/oauth2callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) {
    return res.send(`<h2>Gmail OAuth Error: ${error}</h2><p><a href="/">Return to Dashboard</a></p>`);
  }
  if (!code) {
    return res.send('<h2>Missing authorization code</h2><p><a href="/">Return to Dashboard</a></p>');
  }

  const result = await gmailService.handleOAuthCallback(code);
  if (result.success) {
    res.redirect('/?oauth=success');
  } else {
    res.send(`<h2>OAuth Connection Failed</h2><p>${result.error}</p><p><a href="/">Return to Dashboard</a></p>`);
  }
});

app.post('/api/gmail/sync-now', async (req, res) => {
  if (!gmailService.isAuthenticated()) {
    return res.status(401).json({ error: 'Gmail not connected. Please authenticate via OAuth first.' });
  }
  await monitoringWorker._runScanCycle();
  res.json({ success: true, message: 'Live Gmail inbox synchronization initiated' });
});

app.post('/api/gmail/disconnect', (req, res) => {
  gmailService.disconnect();
  res.json({ success: true, message: 'Gmail disconnected. Switched to Demo Simulation Mode.' });
});

// Catch-all to dashboard
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`  🔬 ThreatLens AI Email Security Engine active`);
  console.log(`  🌐 Web SOC Dashboard & Demo Client: http://localhost:${PORT}`);
  console.log(`  🛡️  24/7 Monitoring Engine: Protection Active`);
  console.log(`=======================================================`);
});

export default app;
