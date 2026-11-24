// ============================================================
// MESSAGE REPOSITORY
// Idempotent message storage — core dedup key: gmail_message_id
// ============================================================

import { getDb } from '../db.js';

export class MessageRepo {
  static findByGmailId(gmailMessageId) {
    return getDb().prepare(
      'SELECT * FROM messages WHERE gmail_message_id = ?'
    ).get(gmailMessageId) || null;
  }

  static upsert(data) {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO messages (
        gmail_message_id, account_id, thread_id, subject, from_raw, from_name, from_email,
        to_raw, date_raw, received_at, snippet, folder, processing_status, is_demo
      ) VALUES (
        @gmail_message_id, @account_id, @thread_id, @subject, @from_raw, @from_name, @from_email,
        @to_raw, @date_raw, @received_at, @snippet, @folder, @processing_status, @is_demo
      )
      ON CONFLICT(gmail_message_id) DO UPDATE SET
        processing_status = excluded.processing_status,
        folder = excluded.folder
      RETURNING *
    `);
    return stmt.get({
      gmail_message_id: data.gmail_message_id,
      account_id: data.account_id || null,
      thread_id: data.thread_id || null,
      subject: data.subject || '(no subject)',
      from_raw: data.from_raw || '',
      from_name: data.from_name || '',
      from_email: data.from_email || '',
      to_raw: data.to_raw || '',
      date_raw: data.date_raw || '',
      received_at: data.received_at || Math.floor(Date.now() / 1000),
      snippet: data.snippet || '',
      folder: data.folder || 'inbox',
      processing_status: data.processing_status || 'pending',
      is_demo: data.is_demo ? 1 : 0,
    });
  }

  static setStatus(gmailMessageId, status) {
    getDb().prepare(
      'UPDATE messages SET processing_status = ? WHERE gmail_message_id = ?'
    ).run(status, gmailMessageId);
  }

  static setFolder(gmailMessageId, folder) {
    getDb().prepare(
      'UPDATE messages SET folder = ? WHERE gmail_message_id = ?'
    ).run(folder, gmailMessageId);
  }

  static getRecentMessages(limit = 50) {
    return getDb().prepare(
      'SELECT * FROM messages ORDER BY created_at DESC LIMIT ?'
    ).all(limit);
  }

  static countAll() {
    return getDb().prepare('SELECT COUNT(*) as c FROM messages').get().c;
  }
}
