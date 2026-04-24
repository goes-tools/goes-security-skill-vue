/**
 * Security HTML Reporter — Vitest edition
 * ───────────────────────────────────────
 * Port of the Jest-based reporter in portafolio-it-be. Keeps the
 * same AllureCompat metadata pipeline (temp JSON files under the
 * OS tmp dir) and the same HTML + Excel output shape so both
 * projects speak the same audit vocabulary.
 *
 * The only real difference vs. the Jest version is the entry-
 * point hook: `onFinished(files, errors)` replaces
 * `onRunComplete(testContexts, results)`. We build the same
 * `results`-shaped object from Vitest's File[] so every downstream
 * helper (buildStatusBreakdown, generateHtml, generateXlsx,
 * generateId) stays untouched.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

class SecurityHtmlReporter {

  constructor(options) {
    const opts = options && (options.outputPath || options.projectName)
      ? options
      : (arguments[1] || {});
    this.options = {
      outputPath: opts.outputPath || './reports/security/security-report.html',
    };
  }

  onInit(ctx) {
    this._vitestCtx = ctx;
  }

  /**
   * Vitest 1.x/2.x hook — receives every `File` (test file) with
   * its task tree. Kept for backwards compat.
   */
  async onFinished(files, errors) {
    await this._emitReport(files || [], errors || []);
  }

  /**
   * Vitest 3.x / 4.x hook — replaces `onFinished`. Receives
   * `TestModule[]` with methods like `.children.allTests()`.
   * We normalise both shapes into a Jest-looking `results` object.
   */
  async onTestRunEnd(testModules, unhandledErrors) {
    // TestModules have `moduleId` + `task` (old File-shaped tree).
    // Fall back to the underlying task tree so the collector below
    // works without knowing which API we are on.
    const files = [];
    for (const mod of testModules || []) {
      const file = mod.task || mod; // Vitest 3/4 keeps .task
      if (file) files.push(file);
    }
    await this._emitReport(files, unhandledErrors || []);
  }

  async _emitReport(files, errors) {
    const results = this.toJestResults(files || []);
    await this.onRunComplete(undefined, results);
    if (errors && errors.length > 0) {
      for (const err of errors) {
        console.warn('⚠️  Security suite error:', err?.message || err);
      }
    }
  }

  /** Recursively flattens a Vitest task tree into a flat test list. */
  collectTasks(tasks, into, filePath, prefix) {
    for (const task of tasks || []) {
      if (task.type === 'suite') {
        const nextPrefix = prefix ? prefix + ' > ' + task.name : task.name;
        this.collectTasks(task.tasks, into, filePath, nextPrefix);
        continue;
      }
      if (task.type === 'test' || task.mode === 'run' || task.name) {
        const state = task.result?.state || task.mode;
        const status =
          state === 'pass' ? 'passed'
          : state === 'fail' ? 'failed'
          : state === 'skip' || state === 'todo' ? 'pending'
          : 'pending';
        into.push({
          title: task.name || '',
          fullName: prefix ? prefix + ' > ' + task.name : task.name,
          status,
          duration: task.result?.duration || 0,
          failureMessages:
            (task.result?.errors || []).map((e) => e?.stack || e?.message || String(e)),
        });
      }
    }
  }

  /** Builds a Jest-shape `results` object from Vitest's File[]. */
  toJestResults(files) {
    const testResults = [];
    let numPassedTests = 0;
    let numFailedTests = 0;
    let numPendingTests = 0;
    let numTotalTests = 0;
    for (const file of files) {
      const list = [];
      this.collectTasks(file.tasks, list, file.filepath, '');
      for (const t of list) {
        numTotalTests++;
        if (t.status === 'passed') numPassedTests++;
        else if (t.status === 'failed') numFailedTests++;
        else numPendingTests++;
      }
      testResults.push({
        testFilePath: file.filepath,
        testResults: list,
        perfStats: {
          start: file.result?.startTime || 0,
          end: (file.result?.startTime || 0) + (file.result?.duration || 0),
        },
      });
    }
    return {
      testResults,
      numTotalTests,
      numPassedTests,
      numFailedTests,
      numPendingTests,
    };
  }

  async onRunComplete(
    testContexts,
    results,
  ) {
    const tempDir =
      process.env.SECURITY_REPORTER_TEMP_DIR ||
      path.join(os.tmpdir(), 'security-html-reporter');

    // Read metadata files
    const metadataMap = new Map();
    if (fs.existsSync(tempDir)) {
      const files = fs.readdirSync(tempDir);
      for (const file of files) {
        if (file.startsWith('meta-') && file.endsWith('.json')) {
          try {
            const content = fs.readFileSync(path.join(tempDir, file), 'utf-8');
            const metadata = JSON.parse(content);
            const key = `${metadata.testPath}::${metadata.testName}`;
            metadataMap.set(key, metadata);
          } catch (e) {
            // Skip invalid metadata files
          }
        }
      }
    }

    // Merge test results with metadata
    const mergedTests = [];
    for (const testResult of results.testResults) {
      for (const assertion of testResult.testResults) {
        const key = `${testResult.testFilePath}::${assertion.fullName}`;
        const metadata = metadataMap.get(key);

        const merged = {
          id: this.generateId(),
          name: assertion.title,
          fullName: assertion.fullName,
          status: assertion.status ,
          duration: assertion.duration || 0,
          filePath: testResult.testFilePath,
          errors: assertion.failureMessages || [],
          epic: metadata?.epic,
          feature: metadata?.feature,
          story: metadata?.story,
          severity: metadata?.severity,
          owner: metadata?.owner,
          tags: metadata?.tags || [],
          labels: metadata?.labels || {},
          links: metadata?.links || [],
          description: metadata?.description,
          parameters: metadata?.parameters || [],
          steps: metadata?.steps || [],
          evidences: metadata?.evidences || [],
        };

        mergedTests.push(merged);
      }
    }

    // Build summary
    const summary = {
      total: results.numTotalTests,
      passed: results.numPassedTests,
      failed: results.numFailedTests,
      skipped: results.numPendingTests,
      suites: results.testResults.length,
    };

    // Extra derived sections for the dashboard and the xlsx.
    const statusBreakdown = this.buildStatusBreakdown(mergedTests);
    const owaspBreakdown = this.buildOwaspBreakdown(mergedTests);

    const reportData = {
      meta: {
        generatedAt: new Date().toISOString(),
        duration: results.testResults.reduce((acc, r) => acc + (r.perfStats?.end - r.perfStats?.start || 0), 0),
        project: 'Portafolio IT Frontend',
      },
      summary,
      statusBreakdown,
      owaspBreakdown,
      tests: mergedTests,
    };

    // Generate HTML
    const html = this.generateHtml(reportData);

    // Write file
    const outputDir = path.dirname(this.options.outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(this.options.outputPath, html, 'utf-8');

    // Sibling artifact — Excel workbook. Lives next to the HTML so
    // the link in the report can use a relative basename reference.
    const xlsxPath = this.options.outputPath.replace(/\.html$/, '.xlsx');
    try {
      this.generateXlsx(reportData, xlsxPath);
    } catch (err) {
      console.warn('⚠️  Could not generate Excel report:', err.message);
    }

    // Log success
    const absPath = path.resolve(this.options.outputPath);
    console.log(
      `\n📊 Security Report generated: ${absPath}`,
    );
    console.log(
      `   ${summary.total} tests | ${summary.passed} passed | ${summary.failed} failed | ${reportData.meta.duration}ms`,
    );
    if (fs.existsSync(xlsxPath)) {
      console.log(`   📑 Excel:  ${path.resolve(xlsxPath)}`);
    }

    // Cleanup temp files
    if (fs.existsSync(tempDir)) {
      try {
        const files = fs.readdirSync(tempDir);
        for (const file of files) {
          if (file.startsWith('meta-') && file.endsWith('.json')) {
            fs.unlinkSync(path.join(tempDir, file));
          }
        }
      } catch (e) {
        // Cleanup errors are non-critical
      }
    }
  }

  generateId() {
    return Math.random().toString(36).substring(2, 11);
  }

  // ──────────────────────────────────────────────────────────
  // EXTENSIONS (added to the local copy of the reporter)
  //
  //  · buildStatusBreakdown — splits tests into passed /
  //    failed / deactivated / migrated / n-a for the dashboard
  //    and the Excel workbook.
  //  · buildOwaspBreakdown — counts tests per OWASP Top 10
  //    category using the `OWASP-A\d+` tags.
  //  · generateXlsx — writes a sibling `.xlsx` file using
  //    SheetJS. The HTML exposes a "Descargar Excel" link.
  // ──────────────────────────────────────────────────────────

  /** Categorise each merged test entry by intent-driven status. */
  buildStatusBreakdown(tests) {
    const bucket = {
      passed: 0,
      failed: 0,
      skipped: 0,
      notApplicable: 0,
      deactivated: 0,
      migrated: 0,
    };
    for (const t of tests) {
      const tags = (t.tags || []).map((s) => String(s).toLowerCase());
      const statusLabel = (t.labels && t.labels.status ? String(t.labels.status) : '').toLowerCase();
      if (t.status === 'failed') {
        bucket.failed++;
      } else if (t.status === 'skipped' || t.status === 'pending') {
        bucket.skipped++;
      } else if (tags.includes('n/a') || statusLabel === 'not-applicable') {
        bucket.notApplicable++;
      } else if (tags.includes('deactivated') || statusLabel === 'deactivated') {
        bucket.deactivated++;
      } else if (tags.includes('migrated') || statusLabel === 'migrated') {
        bucket.migrated++;
      } else if (t.status === 'passed') {
        bucket.passed++;
      }
    }
    return bucket;
  }

  /** Counts tests per OWASP Top 10 category (A01 … A10). */
  buildOwaspBreakdown(tests) {
    const counts = {};
    for (const t of tests) {
      for (const rawTag of t.tags || []) {
        const m = String(rawTag).toUpperCase().match(/OWASP-?(A\d{2})/);
        if (m) {
          counts[m[1]] = (counts[m[1]] || 0) + 1;
        }
      }
    }
    return counts;
  }

  /**
   * Extracts GOES-R\d+ identifiers from tags and groups tests under
   * each requirement. Tests that do not carry a requirement are
   * excluded from the matrix (they appear in the main test list
   * regardless).
   */
  /**
   * Writes a sibling `.xlsx` file next to the HTML. One sheet per
   * intent bucket (Passed / Deactivated / Migrated / N/A / Failed)
   * plus a Summary sheet.
   */
  generateXlsx(reportData, outputPath) {
    let XLSX;
    try {
      // Lazy-required so the reporter still works (HTML only) if
      // the dev dependency was not installed for some reason.
      XLSX = require('xlsx');
    } catch {
      console.warn('⚠️  `xlsx` not installed — skipping Excel generation.');
      return;
    }

    const wb = XLSX.utils.book_new();

    // ── Summary sheet ─────────────────────────────────────
    const summaryRows = [
      ['Proyecto', reportData.meta.project],
      ['Generado', reportData.meta.generatedAt],
      ['Duración (ms)', reportData.meta.duration],
      [],
      ['Total', reportData.summary.total],
      ['Pasados', reportData.statusBreakdown.passed],
      ['Fallidos', reportData.statusBreakdown.failed],
      ['Skipped', reportData.statusBreakdown.skipped],
      ['Desactivados', reportData.statusBreakdown.deactivated],
      ['Migrados', reportData.statusBreakdown.migrated],
      ['No aplicables (N/A)', reportData.statusBreakdown.notApplicable],
    ];
    const summarySheet = XLSX.utils.aoa_to_sheet(summaryRows);
    summarySheet['!cols'] = [{ wch: 26 }, { wch: 60 }];
    XLSX.utils.book_append_sheet(wb, summarySheet, 'Resumen');

    // ── Detailed test list split by bucket ────────────────
    const header = [
      'Archivo',
      'Epic',
      'Feature',
      'Story',
      'Nombre',
      'Estado',
      'Severidad',
      'Tags',
      'Duración (ms)',
      'Descripción',
    ];
    const stripHtml = (s) => String(s || '').replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    const row = (t) => [
      path.basename(t.filePath || ''),
      t.epic || '',
      t.feature || '',
      t.story || '',
      t.name || '',
      this.intentStatusOf(t),
      t.severity || '',
      (t.tags || []).join(', '),
      t.duration || 0,
      stripHtml(t.description),
    ];

    const buckets = {
      Pasados: [],
      Fallidos: [],
      Desactivados: [],
      Migrados: [],
      'No aplicables': [],
    };
    for (const t of reportData.tests) {
      const intent = this.intentStatusOf(t);
      if (intent === 'Pasado') buckets['Pasados'].push(t);
      else if (intent === 'Fallido') buckets['Fallidos'].push(t);
      else if (intent === 'Desactivado') buckets['Desactivados'].push(t);
      else if (intent === 'Migrado') buckets['Migrados'].push(t);
      else if (intent === 'No aplicable') buckets['No aplicables'].push(t);
    }
    for (const [sheetName, items] of Object.entries(buckets)) {
      if (items.length === 0) continue;
      const sheet = XLSX.utils.aoa_to_sheet([header, ...items.map(row)]);
      sheet['!cols'] = [
        { wch: 30 },
        { wch: 24 },
        { wch: 24 },
        { wch: 30 },
        { wch: 60 },
        { wch: 14 },
        { wch: 10 },
        { wch: 26 },
        { wch: 10 },
        { wch: 80 },
      ];
      XLSX.utils.book_append_sheet(wb, sheet, sheetName);
    }

    XLSX.writeFile(wb, outputPath);
  }

  /** Maps raw jest status + tags to a Spanish intent label. */
  intentStatusOf(t) {
    const tags = (t.tags || []).map((s) => String(s).toLowerCase());
    const statusLabel = (t.labels && t.labels.status ? String(t.labels.status) : '').toLowerCase();
    if (t.status === 'failed') return 'Fallido';
    if (t.status === 'skipped' || t.status === 'pending') return 'Skipped';
    if (tags.includes('n/a') || statusLabel === 'not-applicable') return 'No aplicable';
    if (tags.includes('deactivated') || statusLabel === 'deactivated') return 'Desactivado';
    if (tags.includes('migrated') || statusLabel === 'migrated') return 'Migrado';
    if (t.status === 'passed') return 'Pasado';
    return t.status || 'Otro';
  }

  generateHtml(reportData) {
    const dataJson = JSON.stringify(reportData).replace(/</g, '\\x3c').replace(/>/g, '\\x3e');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Test Report</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
        'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
        sans-serif;
      background: #1a1a2e;
      color: #e8e8e8;
      overflow: hidden;
    }

    .container {
      display: flex;
      height: 100vh;
    }

    .sidebar {
      width: 280px;
      background: #16213e;
      border-right: 1px solid #2a3a4a;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .sidebar-header {
      padding: 16px;
      border-bottom: 1px solid #2a3a4a;
    }

    .search-box {
      width: 100%;
      padding: 8px 12px;
      background: #1a1a2e;
      border: 1px solid #2a3a4a;
      border-radius: 4px;
      color: #e8e8e8;
      font-size: 14px;
      transition: border-color 0.2s;
    }

    .search-box:focus {
      outline: none;
      border-color: #3b82f6;
    }

    .sidebar-content {
      flex: 1;
      overflow-y: auto;
      padding: 12px;
    }

    .sidebar-item {
      padding: 8px 12px;
      cursor: pointer;
      border-radius: 4px;
      margin-bottom: 4px;
      font-size: 13px;
      transition: background-color 0.2s;
      user-select: none;
    }

    .sidebar-item:hover {
      background: #1e2a3a;
    }

    .sidebar-item.active {
      background: #0f3460;
      color: #3b82f6;
    }

    .sidebar-item-header {
      display: flex;
      align-items: center;
      gap: 6px;
      font-weight: 500;
    }

    .sidebar-toggle {
      cursor: pointer;
      user-select: none;
      width: 16px;
      text-align: center;
    }

    .sidebar-item-children {
      margin-left: 12px;
      margin-top: 4px;
    }

    .sidebar-item-children.hidden {
      display: none;
    }

    .sidebar-count {
      font-size: 11px;
      color: #a0a0a0;
      margin-left: auto;
      padding-left: 8px;
    }

    .sidebar-indicator {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      margin-left: 4px;
      flex-shrink: 0;
    }

    .indicator-pass {
      background: #22c55e;
    }

    .indicator-fail {
      background: #ef4444;
    }

    .indicator-mixed {
      background: #eab308;
    }

    .main {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .header {
      padding: 24px;
      border-bottom: 1px solid #2a3a4a;
      background: #1a1a2e;
    }

    .header-title {
      font-size: 28px;
      font-weight: 600;
      margin-bottom: 16px;
    }

    .header-actions {
      display: flex;
      gap: 12px;
    }

    .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      font-size: 13px;
      cursor: pointer;
      transition: background-color 0.2s;
      font-weight: 500;
    }

    .btn-primary {
      background: #3b82f6;
      color: #fff;
    }

    .btn-primary:hover {
      background: #2563eb;
    }

    .charts-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      padding: 24px;
      border-bottom: 1px solid #2a3a4a;
      background: #1a1a2e;
    }

    .chart-card {
      background: #1e2a3a;
      border: 1px solid #2a3a4a;
      border-radius: 6px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 200px;
    }

    .chart-title {
      font-size: 12px;
      font-weight: 600;
      color: #a0a0a0;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .chart-svg {
      width: 100%;
      height: auto;
      max-height: 150px;
    }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      padding: 0 24px 24px 24px;
    }

    .stat-card {
      background: #1e2a3a;
      border: 1px solid #2a3a4a;
      border-radius: 6px;
      padding: 12px;
      text-align: center;
    }

    .stat-label {
      font-size: 11px;
      color: #a0a0a0;
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .stat-value {
      font-size: 20px;
      font-weight: 600;
      color: #e8e8e8;
    }

    .tests-section {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      padding: 24px;
    }

    .tests-header {
      font-size: 14px;
      font-weight: 600;
      color: #a0a0a0;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .tests-table {
      flex: 1;
      overflow-y: auto;
      border: 1px solid #2a3a4a;
      border-radius: 6px;
      background: #1e2a3a;
    }

    .test-row {
      display: grid;
      grid-template-columns: 1fr 120px 200px 80px 80px;
      gap: 12px;
      padding: 12px;
      border-bottom: 1px solid #2a3a4a;
      align-items: center;
      cursor: pointer;
      transition: background-color 0.2s;
    }

    .test-row:hover {
      background: #242f3f;
    }

    .test-row:last-child {
      border-bottom: none;
    }

    .test-name {
      font-size: 13px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .test-severity {
      display: flex;
      gap: 6px;
      align-items: center;
    }

    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
      white-space: nowrap;
    }

    .badge-severity {
      color: #fff;
    }

    .badge-blocker {
      background: #ef4444;
    }

    .badge-critical {
      background: #ef4444;
    }

    .badge-high {
      background: #f97316;
    }

    .badge-normal,
    .badge-medium {
      background: #eab308;
      color: #000;
    }

    .badge-minor {
      background: #22c55e;
    }

    .badge-trivial,
    .badge-low {
      background: #6b7280;
    }

    .badge-tag {
      color: #fff;
      padding: 4px 8px;
      font-size: 10px;
    }

    .badge-owasp {
      background: #3b82f6;
    }

    .badge-goes {
      background: #10b981;
    }

    .badge-other {
      background: #6b7280;
    }

    .test-status {
      text-align: center;
      font-size: 18px;
    }

    .status-pass {
      color: #22c55e;
    }

    .status-fail {
      color: #ef4444;
    }

    .status-skip {
      color: #eab308;
    }

    .test-duration {
      text-align: right;
      font-size: 12px;
      color: #a0a0a0;
    }

    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }

    .modal-overlay.active {
      display: flex;
    }

    .modal {
      background: #1e2a3a;
      border: 1px solid #2a3a4a;
      border-radius: 8px;
      max-width: 700px;
      max-height: 80vh;
      overflow-y: auto;
      width: 90%;
      position: relative;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    }

    .modal-header {
      padding: 20px;
      border-bottom: 1px solid #2a3a4a;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
    }

    .modal-title {
      font-size: 16px;
      font-weight: 600;
      flex: 1;
      line-height: 1.4;
      word-break: break-word;
    }

    .modal-close {
      background: none;
      border: none;
      color: #a0a0a0;
      font-size: 24px;
      cursor: pointer;
      padding: 0;
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .modal-close:hover {
      color: #e8e8e8;
    }

    .modal-content {
      padding: 20px;
    }

    .modal-section {
      margin-bottom: 20px;
    }

    .modal-section:last-child {
      margin-bottom: 0;
    }

    .modal-section-title {
      font-size: 12px;
      font-weight: 600;
      color: #a0a0a0;
      text-transform: uppercase;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid #2a3a4a;
      letter-spacing: 0.5px;
    }

    .classification-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      font-size: 13px;
    }

    .classification-item {
      background: #16213e;
      padding: 8px;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
    }

    .classification-label {
      font-size: 10px;
      color: #a0a0a0;
      text-transform: uppercase;
      margin-bottom: 4px;
      font-weight: 600;
    }

    .classification-value {
      color: #e8e8e8;
      word-break: break-word;
    }

    .description-content {
      background: #16213e;
      padding: 12px;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
      font-size: 13px;
      line-height: 1.6;
    }

    .description-content h2 {
      font-size: 13px;
      margin: 8px 0;
      margin-top: 0;
      color: #3b82f6;
    }

    .description-content h2:first-child {
      margin-top: 0;
    }

    .description-content p {
      margin: 8px 0;
    }

    .description-content p:first-child {
      margin-top: 0;
    }

    .steps-list {
      background: #16213e;
      padding: 12px;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
      font-size: 13px;
    }

    .step-item {
      margin-bottom: 8px;
      display: flex;
      gap: 8px;
    }

    .step-item:last-child {
      margin-bottom: 0;
    }

    .step-number {
      font-weight: 600;
      color: #3b82f6;
      flex-shrink: 0;
    }

    .evidence-code {
      background: #0d1117;
      padding: 12px;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 12px;
      overflow-x: auto;
      color: #7ee787;
      line-height: 1.5;
    }

    .links-list {
      background: #16213e;
      padding: 12px;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
      font-size: 13px;
    }

    .link-item {
      margin-bottom: 8px;
    }

    .link-item:last-child {
      margin-bottom: 0;
    }

    .link-item a {
      color: #3b82f6;
      text-decoration: none;
      word-break: break-all;
    }

    .link-item a:hover {
      text-decoration: underline;
    }

    .modal-status {
      padding: 12px;
      background: #16213e;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
      font-size: 13px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    .status-item {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .error-list {
      background: #16213e;
      padding: 12px;
      border-radius: 4px;
      border: 1px solid #2a3a4a;
      border-left: 3px solid #ef4444;
      font-size: 12px;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      color: #fca5a5;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: #a0a0a0;
      text-align: center;
      padding: 40px;
    }

    .empty-state-icon {
      font-size: 48px;
      margin-bottom: 16px;
      opacity: 0.5;
    }

    .empty-state-text {
      font-size: 14px;
    }

    @media print {
      .sidebar {
        display: none;
      }

      .main {
        width: 100%;
      }

      .header-actions {
        display: none;
      }

      .modal-overlay {
        display: none;
      }

      .tests-table {
        border: none;
        background: transparent;
      }

      .test-row {
        page-break-inside: avoid;
        border: 1px solid #2a3a4a;
        margin-bottom: 8px;
      }

      body {
        background: transparent;
        color: #000;
      }

      .sidebar,
      .header,
      .charts-row,
      .stats-row {
        display: none;
      }
    }

    ::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }

    ::-webkit-scrollbar-track {
      background: #1a1a2e;
    }

    ::-webkit-scrollbar-thumb {
      background: #2a3a4a;
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: #3a4a5a;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="sidebar">
      <div class="sidebar-header">
        <input
          type="text"
          class="search-box"
          id="searchBox"
          placeholder="Search tests..."
        />
      </div>
      <div class="sidebar-content" id="sidebarContent">
        <div class="sidebar-item active" data-filter="all">
          <div class="sidebar-item-header">
            <span>📊 Dashboard</span>
          </div>
        </div>
      </div>
    </div>

    <div class="main">
      <div class="header">
        <div class="header-title">Security Test Report</div>
        <div class="header-actions">
          <!-- Only the Excel download ships in the toolbar. The PDF
               export and the SVG badge were removed because: the
               PDF-via-print was a lossy representation, and the badge
               was never embedded into the report itself. -->
          <a class="btn btn-primary" href="security-report.xlsx" download>
            📑 Descargar Excel
          </a>
        </div>
      </div>

      <div class="charts-row" id="chartsRow"></div>
      <div class="stats-row" id="statsRow"></div>

      <div class="tests-section">
        <div class="tests-header">Test Results</div>
        <div class="tests-table" id="testsTable"></div>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="modalOverlay">
    <div class="modal" id="modal"></div>
  </div>

  <script>
    const DATA = ${dataJson};

    let currentFilter = 'all';
    let filteredTests = DATA.tests;

    function init() {
      buildSidebar();
      renderCharts();
      renderStats();
      renderTests();
      setupSearch();
    }

    function buildSidebar() {
      const content = document.getElementById('sidebarContent');
      const tree = buildTree();

      for (const [key, node] of Object.entries(tree)) {
        const item = createSidebarNode(key, node);
        content.appendChild(item);
      }
    }

    function buildTree() {
      const tree = {};

      for (const test of DATA.tests) {
        const epic = test.epic || 'Uncategorized';
        const feature = test.feature || 'Ungrouped';
        const story = test.story || 'No story';

        if (!tree[epic]) {
          tree[epic] = { children: {}, tests: [] };
        }

        if (!tree[epic].children[feature]) {
          tree[epic].children[feature] = { children: {}, tests: [] };
        }

        if (!tree[epic].children[feature].children[story]) {
          tree[epic].children[feature].children[story] = { tests: [] };
        }

        tree[epic].children[feature].children[story].tests.push(test);
        tree[epic].tests.push(test);
        tree[epic].children[feature].tests.push(test);
      }

      return tree;
    }

    function createSidebarNode(key, node, depth = 0) {
      const container = document.createElement('div');
      const item = document.createElement('div');
      item.className = 'sidebar-item';

      const hasChildren = Object.keys(node.children || {}).length > 0;
      const passCount = node.tests.filter((t) => t.status === 'passed').length;
      const failCount = node.tests.filter((t) => t.status === 'failed').length;
      const indicator = failCount > 0 ? 'fail' : 'pass';

      const html = \`
        <div class="sidebar-item-header">
          \${
            hasChildren
              ? \`<span class="sidebar-toggle" onclick="toggleChildren(event)">▼</span>\`
              : '<span style="width: 16px;"></span>'
          }
          <span>\${escapeHtml(key)}</span>
          <span class="sidebar-count">\${node.tests.length}</span>
          <div class="sidebar-indicator indicator-\${indicator}"></div>
        </div>
      \`;

      item.innerHTML = html;
      item.onclick = (e) => {
        if (
          e.target.closest('.sidebar-toggle') ||
          e.target.closest('.sidebar-indicator')
        ) {
          return;
        }
        filterByNode(item, node.tests);
      };

      container.appendChild(item);

      if (hasChildren) {
        const childrenContainer = document.createElement('div');
        childrenContainer.className = 'sidebar-item-children';

        for (const [childKey, childNode] of Object.entries(node.children || {})) {
          childrenContainer.appendChild(createSidebarNode(childKey, childNode, depth + 1));
        }

        container.appendChild(childrenContainer);
      }

      return container;
    }

    function toggleChildren(e) {
      e.stopPropagation();
      const target = e.target.closest('.sidebar-toggle');
      const container = target.closest('.sidebar-item').parentElement;
      const children = container.querySelector('.sidebar-item-children');

      if (children) {
        children.classList.toggle('hidden');
        target.textContent = children.classList.contains('hidden') ? '▶' : '▼';
      }
    }

    function filterByNode(item, tests) {
      document.querySelectorAll('.sidebar-item.active').forEach((el) => {
        el.classList.remove('active');
      });

      item.classList.add('active');
      filteredTests = tests;
      renderTests();
    }

    function setupSearch() {
      const searchBox = document.getElementById('searchBox');
      searchBox.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();

        if (!query) {
          filteredTests = DATA.tests;
        } else {
          filteredTests = DATA.tests.filter((test) => {
            const name = test.name.toLowerCase();
            const fullName = test.fullName.toLowerCase();
            const tags = test.tags.map((t) => t.toLowerCase()).join(' ');
            const epic = (test.epic || '').toLowerCase();
            const feature = (test.feature || '').toLowerCase();
            const story = (test.story || '').toLowerCase();

            return (
              name.includes(query) ||
              fullName.includes(query) ||
              tags.includes(query) ||
              epic.includes(query) ||
              feature.includes(query) ||
              story.includes(query)
            );
          });
        }

        renderTests();
      });
    }

    function renderCharts() {
      const chartsRow = document.getElementById('chartsRow');

      const statusChart = createStatusChart();
      const severityChart = createSeverityChart();
      const owaspChart = createOwaspChart();

      const statusCard = document.createElement('div');
      statusCard.className = 'chart-card';
      statusCard.innerHTML = \`
        <div class="chart-title">Test Status</div>
        \${statusChart}
      \`;

      const severityCard = document.createElement('div');
      severityCard.className = 'chart-card';
      severityCard.innerHTML = \`
        <div class="chart-title">Severity Distribution</div>
        \${severityChart}
      \`;

      const owaspCard = document.createElement('div');
      owaspCard.className = 'chart-card';
      owaspCard.innerHTML = \`
        <div class="chart-title">OWASP Coverage</div>
        \${owaspChart}
      \`;

      chartsRow.appendChild(statusCard);
      chartsRow.appendChild(severityCard);
      chartsRow.appendChild(owaspCard);
    }

    function createStatusChart() {
      const total = DATA.summary.total;
      const passed = DATA.summary.passed;
      const failed = DATA.summary.failed;
      const skipped = DATA.summary.skipped;

      const passPercent = (passed / total) * 100;
      const failPercent = (failed / total) * 100;
      const skipPercent = (skipped / total) * 100;

      const size = 120;
      const radius = size / 2 - 10;

      const passAngle = (passPercent / 100) * 360;
      const failAngle = (failPercent / 100) * 360;
      const skipAngle = (skipPercent / 100) * 360;

      const passPath = getArcPath(size / 2, size / 2, radius, 0, passAngle);
      const failPath = getArcPath(
        size / 2,
        size / 2,
        radius,
        passAngle,
        passAngle + failAngle,
      );
      const skipPath = getArcPath(
        size / 2,
        size / 2,
        radius,
        passAngle + failAngle,
        360,
      );

      return \`
        <svg class="chart-svg" viewBox="0 0 \${size} \${size}" width="\${size}" height="\${size}">
          <path d="\${passPath}" fill="#22c55e" stroke="none" />
          \${failPercent > 0 ? \`<path d="\${failPath}" fill="#ef4444" stroke="none" />\` : ''}
          \${skipPercent > 0 ? \`<path d="\${skipPath}" fill="#eab308" stroke="none" />\` : ''}
          <circle cx="\${size / 2}" cy="\${size / 2}" r="\${radius * 0.55}" fill="#1e2a3a" />
          <text x="\${size / 2}" y="\${size / 2}" text-anchor="middle" dy="0.3em" fill="#e8e8e8" font-size="16" font-weight="bold">\${passed}</text>
          <text x="\${size / 2}" y="\${size / 2 + 14}" text-anchor="middle" dy="0.3em" fill="#a0a0a0" font-size="10">passed</text>
        </svg>
        <div style="font-size: 12px; margin-top: 8px; text-align: center;">
          <div style="color: #22c55e;">✓ \${passed} passed</div>
          <div style="color: #ef4444;">✗ \${failed} failed</div>
          <div style="color: #eab308;">⊘ \${skipped} skipped</div>
        </div>
      \`;
    }

    function createSeverityChart() {
      const severities = [
        'blocker',
        'critical',
        'high',
        'normal',
        'medium',
        'minor',
        'trivial',
        'low',
      ];
      const counts = {};

      for (const severity of severities) {
        counts[severity] = DATA.tests.filter((t) => t.severity === severity).length;
      }

      const maxCount = Math.max(...Object.values(counts), 1);
      const chartHeight = 100;
      const barWidth = 8;
      const gap = 2;
      const width = severities.length * (barWidth + gap) + 20;

      let svg = \`<svg class="chart-svg" viewBox="0 0 \${width} \${chartHeight + 20}" width="\${width}" height="\${chartHeight + 20}">\`;

      let x = 10;
      for (const severity of severities) {
        const count = counts[severity];
        if (count === 0) {
          x += barWidth + gap;
          continue;
        }

        const height = (count / maxCount) * chartHeight;
        const y = chartHeight - height + 10;

        const colorMap = {
          blocker: '#ef4444',
          critical: '#ef4444',
          high: '#f97316',
          normal: '#eab308',
          medium: '#eab308',
          minor: '#22c55e',
          trivial: '#6b7280',
          low: '#6b7280',
        };

        svg += \`<rect x="\${x}" y="\${y}" width="\${barWidth}" height="\${height}" fill="\${colorMap[severity]}" rx="1" />\`;
        svg += \`<text x="\${x + barWidth / 2}" y="\${chartHeight + 15}" text-anchor="middle" font-size="8" fill="#a0a0a0">\${severity.substring(0, 3)}</text>\`;

        x += barWidth + gap;
      }

      svg += '</svg>';
      return svg;
    }

    function createOwaspChart() {
      const owaspMap = {};

      for (const test of DATA.tests) {
        for (const tag of test.tags) {
          if (tag.startsWith('OWASP')) {
            owaspMap[tag] = (owaspMap[tag] || 0) + 1;
          }
        }
      }

      const owaspEntries = Object.entries(owaspMap).sort(
        ([, a], [, b]) => b - a,
      );
      const topOwasp = owaspEntries.slice(0, 5);

      if (topOwasp.length === 0) {
        return '<div style="text-align: center; color: #a0a0a0; padding: 20px;">No OWASP tags found</div>';
      }

      const size = 120;
      const startAngle = -90;
      let currentAngle = startAngle;
      const totalCount = topOwasp.reduce((acc, [, count]) => acc + count, 0);

      const colors = ['#3b82f6', '#10b981', '#f97316', '#8b5cf6', '#ec4899'];

      let svg = \`<svg class="chart-svg" viewBox="0 0 \${size} \${size}" width="\${size}" height="\${size}">\`;

      for (let i = 0; i < topOwasp.length; i++) {
        const [label, count] = topOwasp[i];
        const angle = (count / totalCount) * 360;
        const path = getDonutPath(size / 2, size / 2, 35, 50, currentAngle, currentAngle + angle);

        svg += \`<path d="\${path}" fill="\${colors[i % colors.length]}" stroke="#1e2a3a" stroke-width="1" />\`;

        currentAngle += angle;
      }

      svg += \`<circle cx="\${size / 2}" cy="\${size / 2}" r="30" fill="#1e2a3a" />\`;
      svg += '</svg>';

      return (
        svg +
        '<div style="font-size: 11px; margin-top: 8px;">' +
        topOwasp
          .map(
            ([label, count], i) =>
              \`<div style="color: \${colors[i % colors.length]}; margin-bottom: 4px;">\${label}: \${count}</div>\`,
          )
          .join('') +
        '</div>'
      );
    }

    function getArcPath(cx, cy, r, startAngle, endAngle) {
      const start = polarToCartesian(cx, cy, r, endAngle);
      const end = polarToCartesian(cx, cy, r, startAngle);
      const largeArc = endAngle - startAngle <= 180 ? '0' : '1';

      return [
        'M',
        cx,
        cy,
        'L',
        start.x,
        start.y,
        'A',
        r,
        r,
        0,
        largeArc,
        0,
        end.x,
        end.y,
        'Z',
      ].join(' ');
    }

    function getDonutPath(cx, cy, innerR, outerR, startAngle, endAngle) {
      const outerStart = polarToCartesian(cx, cy, outerR, endAngle);
      const outerEnd = polarToCartesian(cx, cy, outerR, startAngle);
      const innerStart = polarToCartesian(cx, cy, innerR, endAngle);
      const innerEnd = polarToCartesian(cx, cy, innerR, startAngle);

      const largeArc = endAngle - startAngle <= 180 ? '0' : '1';

      return [
        'M',
        outerStart.x,
        outerStart.y,
        'A',
        outerR,
        outerR,
        0,
        largeArc,
        0,
        outerEnd.x,
        outerEnd.y,
        'L',
        innerEnd.x,
        innerEnd.y,
        'A',
        innerR,
        innerR,
        0,
        largeArc,
        1,
        innerStart.x,
        innerStart.y,
        'Z',
      ].join(' ');
    }

    function polarToCartesian(cx, cy, r, angle) {
      const radians = ((angle - 90) * Math.PI) / 180.0;
      return {
        x: cx + r * Math.cos(radians),
        y: cy + r * Math.sin(radians),
      };
    }

    function renderStats() {
      const statsRow = document.getElementById('statsRow');

      const stats = [
        {
          label: 'Total Tests',
          value: DATA.summary.total,
        },
        {
          label: 'Passed',
          value: DATA.summary.passed,
        },
        {
          label: 'Failed',
          value: DATA.summary.failed,
        },
        {
          label: 'Skipped',
          value: DATA.summary.skipped,
        },
        {
          label: 'Duration',
          value: \`\${(DATA.meta.duration / 1000).toFixed(1)}s\`,
        },
      ];

      for (const stat of stats) {
        const card = document.createElement('div');
        card.className = 'stat-card';
        card.innerHTML = \`
          <div class="stat-label">\${stat.label}</div>
          <div class="stat-value">\${stat.value}</div>
        \`;
        statsRow.appendChild(card);
      }
    }

    function renderTests() {
      const table = document.getElementById('testsTable');
      table.innerHTML = '';

      if (filteredTests.length === 0) {
        table.innerHTML = \`
          <div class="empty-state">
            <div class="empty-state-icon">🔍</div>
            <div class="empty-state-text">No tests match your filter</div>
          </div>
        \`;
        return;
      }

      const sorted = [...filteredTests].sort((a, b) => {
        const severityOrder = [
          'blocker',
          'critical',
          'high',
          'normal',
          'medium',
          'minor',
          'trivial',
          'low',
        ];
        const aIndex = severityOrder.indexOf(a.severity || 'low');
        const bIndex = severityOrder.indexOf(b.severity || 'low');

        if (aIndex !== bIndex) {
          return aIndex - bIndex;
        }

        return a.name.localeCompare(b.name);
      });

      for (const test of sorted) {
        const row = document.createElement('div');
        row.className = 'test-row';

        const statusIcon = {
          passed: '✓',
          failed: '✗',
          skipped: '⊘',
        }[test.status];

        const statusClass = \`status-\${test.status}\`;

        const tags = test.tags
          .slice(0, 2)
          .map((tag) => {
            let badgeClass = 'badge-other';
            if (tag.startsWith('OWASP')) {
              badgeClass = 'badge-owasp';
            } else if (tag.startsWith('GOES')) {
              badgeClass = 'badge-goes';
            }

            return \`<span class="badge badge-tag \${badgeClass}">\${escapeHtml(tag)}</span>\`;
          })
          .join('');

        const tagsHtml = test.tags.length > 2 ? tags + \`<span class="badge badge-tag badge-other">+\${test.tags.length - 2}</span>\` : tags;

        row.innerHTML = \`
          <div class="test-name" title="\${escapeHtml(test.fullName)}">\${escapeHtml(test.name)}</div>
          <div class="test-severity">
            \${
              test.severity
                ? \`<span class="badge badge-severity badge-\${test.severity}">\${test.severity.toUpperCase()}</span>\`
                : ''
            }
          </div>
          <div class="test-severity">\${tagsHtml}</div>
          <div class="test-status \${statusClass}">\${statusIcon}</div>
          <div class="test-duration">\${test.duration}ms</div>
        \`;

        row.addEventListener('click', () => openModal(test));
        table.appendChild(row);
      }
    }

    function openModal(test) {
      const modal = document.getElementById('modal');
      const overlay = document.getElementById('modalOverlay');

      const statusIcon = {
        passed: '✓',
        failed: '✗',
        skipped: '⊘',
      }[test.status];

      const statusColor = {
        passed: '#22c55e',
        failed: '#ef4444',
        skipped: '#eab308',
      }[test.status];

      let content = \`
        <div class="modal-header">
          <div>
            <div class="modal-title">\${escapeHtml(test.fullName)}</div>
          </div>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <div class="modal-content">
          <div class="modal-section">
            <div style="display: flex; gap: 12px; align-items: center; margin-bottom: 16px;">
              \${
                test.severity
                  ? \`<span class="badge badge-severity badge-\${test.severity}">\${test.severity.toUpperCase()}</span>\`
                  : ''
              }
              \${test.tags
                .map((tag) => {
                  let badgeClass = 'badge-other';
                  if (tag.startsWith('OWASP')) {
                    badgeClass = 'badge-owasp';
                  } else if (tag.startsWith('GOES')) {
                    badgeClass = 'badge-goes';
                  }

                  return \`<span class="badge badge-tag \${badgeClass}">\${escapeHtml(tag)}</span>\`;
                })
                .join('')}
            </div>
          </div>
      \`;

      if (test.epic || test.feature || test.story || test.owner) {
        content += \`
          <div class="modal-section">
            <div class="modal-section-title">Classification</div>
            <div class="classification-grid">
              \${test.epic ? \`<div class="classification-item"><div class="classification-label">Epic</div><div class="classification-value">\${escapeHtml(test.epic)}</div></div>\` : ''}
              \${test.feature ? \`<div class="classification-item"><div class="classification-label">Feature</div><div class="classification-value">\${escapeHtml(test.feature)}</div></div>\` : ''}
              \${test.story ? \`<div class="classification-item"><div class="classification-label">Story</div><div class="classification-value">\${escapeHtml(test.story)}</div></div>\` : ''}
              \${test.owner ? \`<div class="classification-item"><div class="classification-label">Owner</div><div class="classification-value">\${escapeHtml(test.owner)}</div></div>\` : ''}
            </div>
          </div>
        \`;
      }

      if (test.description) {
        content += \`
          <div class="modal-section">
            <div class="modal-section-title">Description</div>
            <div class="description-content">\${test.description}</div>
          </div>
        \`;
      }

      if (test.steps.length > 0) {
        content += \`
          <div class="modal-section">
            <div class="modal-section-title">Steps</div>
            <div class="steps-list">
              \${test.steps
                .map(
                  (step, i) =>
                    \`<div class="step-item"><span class="step-number">\${i + 1}.</span> <span>\${escapeHtml(step)}</span></div>\`,
                )
                .join('')}
            </div>
          </div>
        \`;
      }

      if (test.evidences.length > 0) {
        content += \`
          <div class="modal-section">
            <div class="modal-section-title">Evidence</div>
            \${test.evidences
              .map(
                (evidence) =>
                  \`<div style="margin-bottom: 12px;"><div style="font-size: 12px; color: #a0a0a0; margin-bottom: 6px;">\${escapeHtml(evidence.name)}</div><pre class="evidence-code">\${escapeHtml(JSON.stringify(evidence.data, null, 2))}</pre></div>\`,
              )
              .join('')}
          </div>
        \`;
      }

      if (test.links.length > 0) {
        content += \`
          <div class="modal-section">
            <div class="modal-section-title">Links</div>
            <div class="links-list">
              \${test.links
                .map(
                  (link) =>
                    \`<div class="link-item">🔗 <a href="\${escapeHtml(link.url)}" target="_blank" rel="noopener">\${escapeHtml(link.name)}</a></div>\`,
                )
                .join('')}
            </div>
          </div>
        \`;
      }

      if (test.errors.length > 0) {
        content += \`
          <div class="modal-section">
            <div class="modal-section-title">Errors</div>
            <div class="error-list">\${test.errors.map((err) => escapeHtml(err)).join('\\n\\n')}</div>
          </div>
        \`;
      }

      content += \`
        <div class="modal-section">
          <div class="modal-status">
            <div class="status-item">
              <span style="color: \${statusColor}; font-size: 18px;">\${statusIcon}</span>
              <span>Status: <strong>\${test.status.toUpperCase()}</strong></span>
            </div>
            <div class="status-item">
              <span>Duration: <strong>\${test.duration}ms</strong></span>
            </div>
          </div>
        </div>
      \`;

      modal.innerHTML = content;
      overlay.classList.add('active');
    }

    function closeModal() {
      document.getElementById('modalOverlay').classList.remove('active');
    }

    function escapeHtml(text) {
      if (!text) return '';
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    document.getElementById('modalOverlay').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) {
        closeModal();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeModal();
      }
    });

    init();
  </script>
</body>
</html>
`;
  }
}

module.exports = SecurityHtmlReporter;
