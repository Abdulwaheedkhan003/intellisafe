// ============================================================
// DATABASE SCHEMA — All table definitions
// Runs on first startup, idempotent (CREATE TABLE IF NOT EXISTS)
// ============================================================

export function initializeSchema(db) {
  db.exec(`
    -- Gmail accounts connected by users
    CREATE TABLE IF NOT EXISTS gmail_accounts (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      email             TEXT NOT NULL UNIQUE,
      access_token_enc  TEXT,
      refresh_token_enc TEXT,
      history_id        TEXT,
      watch_expiry      INTEGER,
      connected_at      INTEGER DEFAULT (unixepoch()),
      last_sync_at      INTEGER,
      is_active         INTEGER DEFAULT 1
    );

    -- Individual email messages retrieved from Gmail
    CREATE TABLE IF NOT EXISTS messages (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      gmail_message_id TEXT NOT NULL UNIQUE,  -- Idempotency key
      account_id       INTEGER REFERENCES gmail_accounts(id),
      thread_id        TEXT,
      subject          TEXT,
      from_raw         TEXT,
      from_name        TEXT,
      from_email       TEXT,
      to_raw           TEXT,
      date_raw         TEXT,
      received_at      INTEGER,
      snippet          TEXT,
      folder           TEXT DEFAULT 'inbox',
      processing_status TEXT DEFAULT 'pending',  -- pending|processing|done|error
      is_demo          INTEGER DEFAULT 0,
      created_at       INTEGER DEFAULT (unixepoch())
    );

    -- Full security investigations (one per message)
    CREATE TABLE IF NOT EXISTS investigations (
      id                   INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id           INTEGER NOT NULL UNIQUE REFERENCES messages(id),
      risk_score           INTEGER DEFAULT 0,
      severity             TEXT DEFAULT 'SAFE',
      confidence           REAL DEFAULT 0,
      primary_category_id  TEXT,
      primary_category_name TEXT,
      secondary_categories TEXT,  -- JSON array
      ai_summary           TEXT,
      ai_key_factors       TEXT,  -- JSON array
      human_explanation    TEXT,
      recommended_action   TEXT DEFAULT 'ALLOW',
      policy_decision      TEXT DEFAULT 'ALLOW',
      executed_action      TEXT DEFAULT 'ALLOW',
      intel_status         TEXT DEFAULT 'UNAVAILABLE',
      investigation_timeline TEXT,  -- JSON array
      is_threat            INTEGER DEFAULT 0,
      created_at           INTEGER DEFAULT (unixepoch())
    );

    -- Individual evidence items (many per investigation)
    CREATE TABLE IF NOT EXISTS evidence (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      investigation_id  INTEGER NOT NULL REFERENCES investigations(id),
      type              TEXT,
      signal            TEXT,
      finding           TEXT,
      value_json        TEXT,  -- JSON
      source            TEXT,
      severity          TEXT,
      confidence        REAL,
      verified          INTEGER DEFAULT 1,
      verification_status TEXT DEFAULT 'VERIFIED'
    );

    -- Notifications queued for the extension
    CREATE TABLE IF NOT EXISTS notifications (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      investigation_id INTEGER REFERENCES investigations(id),
      type             TEXT,  -- threat|quarantine|spam|safe|error
      title            TEXT,
      body             TEXT,
      category         TEXT,
      risk_score       INTEGER,
      action_taken     TEXT,
      read             INTEGER DEFAULT 0,
      created_at       INTEGER DEFAULT (unixepoch())
    );

    -- Full audit trail for every automated action
    CREATE TABLE IF NOT EXISTS audit_log (
      id                   INTEGER PRIMARY KEY AUTOINCREMENT,
      gmail_message_id     TEXT,
      investigation_id     INTEGER,
      timestamp            INTEGER DEFAULT (unixepoch()),
      category             TEXT,
      risk_score           INTEGER,
      ai_recommendation    TEXT,
      policy_decision      TEXT,
      executed_action      TEXT,
      reason               TEXT,
      execution_ok         INTEGER DEFAULT 1,
      error_msg            TEXT
    );

    -- Indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_messages_gmail_id ON messages(gmail_message_id);
    CREATE INDEX IF NOT EXISTS idx_investigations_message ON investigations(message_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
  `);
}
