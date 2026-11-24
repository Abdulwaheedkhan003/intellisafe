// ============================================================
// ATTACHMENT DETECTOR
// Analyses email attachments for dangerous file types, malicious
// patterns, and suspicious properties.
// ============================================================

const AttachmentDetector = {

  // File extensions grouped by risk level
  EXECUTABLE_EXTENSIONS: [
    '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.msi', '.ps1', '.psm1', '.psd1', '.reg',
    '.hta', '.cpl', '.inf', '.sys', '.drv',
  ],

  OFFICE_EXTENSIONS: ['.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.docm', '.xlsm', '.pptm', '.xlam'],
  MACRO_ENABLED_EXTENSIONS: ['.docm', '.xlsm', '.pptm', '.xlam', '.dotm', '.xltm'],
  SCRIPT_EXTENSIONS: ['.ps1', '.psm1', '.bat', '.cmd', '.sh', '.py', '.rb', '.vbs', '.vbe', '.js', '.jse'],
  ARCHIVE_EXTENSIONS: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.img'],
  PDF_EXTENSIONS: ['.pdf'],
  HTML_EXTENSIONS: ['.html', '.htm', '.mhtml', '.mht'],

  analyze(emailData) {
    const evidence = [];
    const attachments = emailData.attachments || [];

    if (!attachments || attachments.length === 0) {
      return evidence;
    }

    for (const attachment of attachments) {
      const name = (attachment.name || attachment.filename || '').toLowerCase();
      const ext = this._getExtension(name);
      const size = attachment.size || 0;
      const contentType = (attachment.content_type || attachment.mimeType || '').toLowerCase();

      // ─ 1. Executable attachment ─────────────────────────
      if (this.EXECUTABLE_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'executable_attachment',
          finding: `Executable file attached: "${attachment.name || name}" (${ext}) — directly executable files should never be sent via email`,
          verified: true,
          severity: 'CRITICAL',
          attachment_name: attachment.name,
        });
      }

      // ─ 2. Macro-enabled Office document ─────────────────
      if (this.MACRO_ENABLED_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'macro_enabled_document',
          finding: `Macro-enabled Office document attached: "${attachment.name || name}" — macros can execute malicious code automatically`,
          verified: true,
          severity: 'HIGH',
          attachment_name: attachment.name,
        });
        evidence.push({ signal: 'office_attachment', finding: `Office document attached: ${name}`, verified: true, severity: 'MEDIUM' });
      } else if (this.OFFICE_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'office_attachment',
          finding: `Office document attached: "${attachment.name || name}" — review carefully before opening`,
          verified: true,
          severity: 'LOW',
          attachment_name: attachment.name,
        });
      }

      // ─ 3. Script attachment ──────────────────────────────
      if (this.SCRIPT_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'script_attachment',
          finding: `Script file attached: "${attachment.name || name}" (${ext}) — scripts can execute system commands when opened`,
          verified: true,
          severity: 'HIGH',
          attachment_name: attachment.name,
        });
        evidence.push({ signal: 'malicious_script', finding: `Script attachment detected: ${name}`, verified: true, severity: 'HIGH' });
      }

      // ─ 4. Archive attachment ─────────────────────────────
      if (this.ARCHIVE_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'archive_attachment',
          finding: `Archive file attached: "${attachment.name || name}" — archives often contain hidden malicious payloads`,
          verified: true,
          severity: 'MEDIUM',
          attachment_name: attachment.name,
        });

        if (attachment.password_protected) {
          evidence.push({
            signal: 'password_protected_archive',
            finding: `Archive "${attachment.name || name}" is password-protected — used to bypass security scanning`,
            verified: true,
            severity: 'HIGH',
            attachment_name: attachment.name,
          });
        }
      }

      // ─ 5. PDF attachment ─────────────────────────────────
      if (this.PDF_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'pdf_attachment',
          finding: `PDF attachment: "${attachment.name || name}" — PDFs can contain embedded scripts or exploit code`,
          verified: true,
          severity: 'LOW',
          attachment_name: attachment.name,
        });
      }

      // ─ 6. HTML attachment (HTML smuggling) ───────────────
      if (this.HTML_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'html_attachment',
          finding: `HTML attachment: "${attachment.name || name}" — HTML attachments are commonly used for HTML smuggling attacks`,
          verified: true,
          severity: 'HIGH',
          attachment_name: attachment.name,
        });
      }

      // ─ 7. Double extension (deceptive naming) ────────────
      if (this._hasDoubleExtension(name)) {
        evidence.push({
          signal: 'suspicious_attachment',
          finding: `Attachment "${attachment.name || name}" uses a double extension to disguise its true file type`,
          verified: true,
          severity: 'HIGH',
          attachment_name: attachment.name,
        });
      }

      // ─ 8. Executable disguised with document icon via MIME ─
      if (contentType.includes('application/octet-stream') && !this.EXECUTABLE_EXTENSIONS.includes(ext)) {
        evidence.push({
          signal: 'suspicious_attachment',
          finding: `Attachment "${attachment.name || name}" has an executable MIME type but non-executable extension — may be disguised`,
          verified: true,
          severity: 'HIGH',
          attachment_name: attachment.name,
        });
      }

      // ─ 9. Unexpected attachment context ──────────────────
      if (attachments.length > 0 && !emailData.expected_attachment) {
        evidence.push({
          signal: 'unexpected_attachment',
          finding: `Attachment received from an external sender — verify authenticity before opening`,
          verified: true,
          severity: 'LOW',
          attachment_name: attachment.name,
        });
      }
    }

    return evidence;
  },

  _getExtension(filename) {
    if (!filename) return '';
    const parts = filename.split('.');
    return parts.length > 1 ? '.' + parts[parts.length - 1].toLowerCase() : '';
  },

  _hasDoubleExtension(filename) {
    const parts = filename.split('.');
    if (parts.length < 3) return false;
    const secondToLast = '.' + parts[parts.length - 2].toLowerCase();
    return this.EXECUTABLE_EXTENSIONS.includes(secondToLast) ||
           this.SCRIPT_EXTENSIONS.includes(secondToLast);
  },
};

if (typeof window !== 'undefined') window.AttachmentDetector = AttachmentDetector;
