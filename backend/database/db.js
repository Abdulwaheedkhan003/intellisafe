// ============================================================
// DATABASE — SQLite singleton via better-sqlite3
// Zero-config, file-based, no separate server required.
// ============================================================

import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import { initializeSchema } from './schema.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, '../../threatlens.db');

let _db = null;

export function getDb() {
  if (!_db) {
    _db = new Database(DB_PATH, {
      // WAL mode for better concurrent read performance
      pragma: { journal_mode: 'wal', synchronous: 'normal', foreign_keys: 'on' },
    });
    _db.pragma('journal_mode = WAL');
    _db.pragma('foreign_keys = ON');
    initializeSchema(_db);
    console.log('[DB] SQLite connected:', DB_PATH);
  }
  return _db;
}
