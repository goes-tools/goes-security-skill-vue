/**
 * Security Reporter Helper — Metadata Collector
 * ───────────────────────────────────────────────
 * Collects metadata (epic, feature, story, severity, tags, parameters, steps, evidence)
 * per test and writes it to a temp JSON file that the custom SecurityHtmlReporter reads.
 *
 * Compatible with allure-js-commons API for zero-migration from existing Allure tests.
 *
 * Usage:
 *   import { report } from './reporter/metadata';
 *
 *   it('test name', async () => {
 *     const t = report();
 *     t.epic('Input Validation');
 *     t.severity('critical');
 *     t.parameter('email', 'test@goes.gob.sv');
 *     t.step('Validate DTO');
 *     // ... test logic ...
 *     t.evidence('Validation Result', { payload, errors });
 *     await t.flush();
 *   });
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

// ─── Temp directory for metadata files ─────────────────────────
const TEMP_DIR = path.resolve(
  process.env.SECURITY_REPORTER_TEMP_DIR ||
    path.join(os.tmpdir(), 'security-html-reporter'),
);

// Ensure temp directory exists
if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

// ─── Interfaces ─────────────────────────────────────────────────
export interface TestMetadata {
  testName: string;
  testPath: string;
  epic?: string;
  feature?: string;
  story?: string;
  severity?: string;
  owner?: string;
  tags: string[];
  labels: Record<string, string>;
  suite?: string;
  parentSuite?: string;
  links: Array<{ url: string; name: string }>;
  description?: string;
  parameters: Array<{ name: string; value: string }>;
  steps: string[];
  evidences: Array<{ name: string; data: unknown }>;
}

// ─── Reporter Class ─────────────────────────────────────────────
class SecurityTestReporter {
  private meta: TestMetadata = {
    testName: '',
    testPath: '',
    tags: [],
    labels: {},
    links: [],
    parameters: [],
    steps: [],
    evidences: [],
  };

  epic(name: string): this {
    this.meta.epic = name;
    return this;
  }

  feature(name: string): this {
    this.meta.feature = name;
    return this;
  }

  story(name: string): this {
    this.meta.story = name;
    return this;
  }

  severity(level: string): this {
    this.meta.severity = level.toLowerCase();
    return this;
  }

  owner(name: string): this {
    this.meta.owner = name;
    return this;
  }

  tag(...tags: string[]): this {
    this.meta.tags.push(...tags);
    return this;
  }

  label(key: string, value: string): this {
    this.meta.labels[key] = value;
    return this;
  }

  suite(name: string): this {
    this.meta.suite = name;
    return this;
  }

  parentSuite(name: string): this {
    this.meta.parentSuite = name;
    return this;
  }

  link(url: string, name?: string): this {
    this.meta.links.push({ url, name: name || url });
    return this;
  }

  descriptionHtml(html: string): this {
    this.meta.description = html;
    return this;
  }

  parameter(name: string, value: unknown): this {
    let strValue: string;
    if (value == null) {
      strValue = String(value);
    } else if (typeof value === 'string') {
      strValue = value;
    } else {
      strValue = JSON.stringify(value);
    }
    this.meta.parameters.push({ name, value: strValue });
    return this;
  }

  step(name: string, fn?: () => any): any {
    this.meta.steps.push(name);
    if (fn) {
      return fn();
    }
    return this;
  }

  evidence(name: string, data: unknown): this {
    this.meta.evidences.push({ name, data });
    return this;
  }

  /**
   * Flush metadata to a temp JSON file.
   * The custom reporter reads these files in onRunComplete.
   */
  async flush(): Promise<void> {
    // Get current test name and path from Jest's global state
    try {
      const state = expect.getState();
      this.meta.testName = state.currentTestName || '';
      this.meta.testPath = state.testPath || '';
    } catch {
      // Fallback if expect.getState() is not available
    }

    const id = crypto.randomBytes(8).toString('hex');
    const filePath = path.join(TEMP_DIR, `meta-${id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(this.meta, null, 2));
  }
}

// ─── Factory Function ───────────────────────────────────────────
export function report(): SecurityTestReporter {
  return new SecurityTestReporter();
}

/**
 * Compatibility layer: mirrors allure-js-commons API.
 * Use this for minimal migration effort from existing allure-based tests.
 */
export class AllureCompat {
  private reporter = new SecurityTestReporter();

  epic(name: string) { this.reporter.epic(name); }
  feature(name: string) { this.reporter.feature(name); }
  story(name: string) { this.reporter.story(name); }
  severity(level: string) { this.reporter.severity(level); }
  owner(name: string) { this.reporter.owner(name); }
  tag(...tags: string[]) { this.reporter.tag(...tags); }
  label(key: string, value: string) { this.reporter.label(key, value); }
  suite(name: string) { this.reporter.suite(name); }
  parentSuite(name: string) { this.reporter.parentSuite(name); }
  link(url: string, name?: string) { this.reporter.link(url, name); }
  descriptionHtml(html: string) { this.reporter.descriptionHtml(html); }
  parameter(name: string, value: unknown) { this.reporter.parameter(name, value); }

  step(name: string, fn?: () => any): any {
    return this.reporter.step(name, fn);
  }

  async attachment(name: string, data: string, _options?: any) {
    try {
      const parsed = JSON.parse(data);
      this.reporter.evidence(name, parsed);
    } catch {
      this.reporter.evidence(name, data);
    }
  }

  async flush() {
    await this.reporter.flush();
  }
}

/**
 * Get the temp directory path (used by the custom reporter to read metadata files).
 */
export function getMetadataTempDir(): string {
  return TEMP_DIR;
}
