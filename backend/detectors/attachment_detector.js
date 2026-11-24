// ============================================================
// ATTACHMENT DETECTOR — Backend Module
// Analyses attachments for executable payloads, macro documents,
// dangerous scripts, encrypted archives, and HTML smuggling.
// ============================================================

import { EvidenceItem, EVIDENCE_TYPES, VERIFICATION_STATUS } from '../schemas/evidence_schema.js';

export class AttachmentDetector {
  static EXECUTABLE_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.msi', '.ps1', '.psm1', '.psd1', '.reg',
    '.hta', '.cpl', '.inf', '.sys', '.drv',
  ];

  static MACRO_EXTENSIONS = ['.docm', '.xlsm', '.pptm', '.xlam', '.dotm', '.xltm'];
  static SCRIPT_EXTENSIONS = ['.ps1', '.bat', '.cmd', '.sh', '.py', '.rb', '.vbs', '.js', '.wsf'];
  static ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.img'];
  static HTML_EXTENSIONS = ['.html', '.htm', '.mhtml', '.hta', '.svg'];

  static analyze(emailData) {
    const evidence = [];
    const attachments = Array.isArray(emailData.attachments) ? emailData.attachments : [];

    if (attachments.length === 0) {
      return evidence;
    }

    for (const att of attachments) {
      const name = (att.name || att.filename || '').toLowerCase();
      const ext = this._getExtension(name);
      const isPasswordProtected = Boolean(att.password_protected || att.encrypted);

      // 1. Executable file
      if (this.EXECUTABLE_EXTENSIONS.includes(ext)) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.ATTACHMENT,
          signal: 'executable_attachment',
          finding: `Directly executable binary attached: "${att.name || name}" (${ext})`,
          value: { filename: att.name, extension: ext },
          source: 'attachment_detector',
          verified: true,
          confidence: 0.99,
          severity: 'CRITICAL',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }

      // 2. Macro-enabled Office file
      if (this.MACRO_EXTENSIONS.includes(ext)) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.ATTACHMENT,
          signal: 'macro_enabled_document',
          finding: `Macro-enabled document attached: "${att.name || name}" — capable of automated code execution`,
          value: { filename: att.name, extension: ext },
          source: 'attachment_detector',
          verified: true,
          confidence: 0.96,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }

      // 3. Dangerous Script file
      if (this.SCRIPT_EXTENSIONS.includes(ext)) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.ATTACHMENT,
          signal: 'script_attachment',
          finding: `Script file attached: "${att.name || name}" (${ext}) — executes commands when opened`,
          value: { filename: att.name, extension: ext },
          source: 'attachment_detector',
          verified: true,
          confidence: 0.98,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }

      // 4. HTML smuggling payload
      if (this.HTML_EXTENSIONS.includes(ext)) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.ATTACHMENT,
          signal: 'html_attachment',
          finding: `HTML/web file attached: "${att.name || name}" — high risk of HTML smuggling or offline phishing portal`,
          value: { filename: att.name, extension: ext },
          source: 'attachment_detector',
          verified: true,
          confidence: 0.92,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }

      // 5. Password-protected archive
      if (this.ARCHIVE_EXTENSIONS.includes(ext) && isPasswordProtected) {
        evidence.push(new EvidenceItem({
          type: EVIDENCE_TYPES.ATTACHMENT,
          signal: 'password_protected_archive',
          finding: `Encrypted/password-protected archive attached: "${att.name || name}" (commonly used to evade gateway inspection)`,
          value: { filename: att.name, extension: ext },
          source: 'attachment_detector',
          verified: true,
          confidence: 0.93,
          severity: 'HIGH',
          verification_status: VERIFICATION_STATUS.CONFIRMED,
        }));
      }
    }

    if (evidence.length === 0) {
      evidence.push(new EvidenceItem({
        type: EVIDENCE_TYPES.ATTACHMENT,
        signal: 'attachments_appear_safe',
        finding: `${attachments.length} attachment(s) inspected — standard file types with no executable or macro extensions detected`,
        value: { count: attachments.length },
        source: 'attachment_detector',
        verified: true,
        confidence: 0.90,
        severity: 'SAFE',
        verification_status: VERIFICATION_STATUS.CONFIRMED,
      }));
    }

    return evidence;
  }

  static _getExtension(filename) {
    if (!filename) return '';
    const match = filename.match(/\.[a-zA-Z0-9]+$/);
    return match ? match[0].toLowerCase() : '';
  }
}
