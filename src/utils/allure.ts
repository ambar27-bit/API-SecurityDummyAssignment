/**
 * Allure report labelling helpers.
 *
 * Attaches structured metadata to test cases so the Allure report
 * groups findings by severity, area and classification — making the
 * report useful to both engineering and security stakeholders.
 *
 * Usage in a test:
 *   import { label, severity, tag } from '../../src/utils/allure';
 *   test('...', async () => {
 *     label('area', 'Authentication');
 *     severity('critical');
 *     ...
 *   });
 */

import { test } from '@playwright/test';

type Severity = 'blocker' | 'critical' | 'normal' | 'minor' | 'trivial';
type Classification = 'contract' | 'finding' | 'hypothesis';

export function label(name: string, value: string): void {
  test.info().annotations.push({ type: name, description: value });
}

export function severity(level: Severity): void {
  label('severity', level);
}

export function tag(...tags: string[]): void {
  for (const t of tags) {
    label('tag', t);
  }
}

export function securityArea(area: string): void {
  label('feature', area);
}

export function classification(type: Classification): void {
  label('story', type);
}

export function owasp(reference: string): void {
  label('tag', `OWASP: ${reference}`);
}
