/**
 * Playwright global teardown — runs ONCE after all workers finish.
 *
 * Deletes the temporary auth state file written by global-setup.ts.
 * This ensures tokens do not linger on disk after the test run completes,
 * satisfying the security requirement that tokens are not persisted or
 * exposed beyond their necessary lifetime.
 */

import * as fs from 'fs';
import { AUTH_STATE_FILE } from './global-setup';

export default async function globalTeardown(): Promise<void> {
  try {
    if (fs.existsSync(AUTH_STATE_FILE)) {
      fs.unlinkSync(AUTH_STATE_FILE);
      console.log(`\n[Global Teardown] Removed auth state file: ${AUTH_STATE_FILE}`);
    }
  } catch (err) {
    // Non-fatal — log but don't fail the run
    console.warn(`[Global Teardown] Could not remove auth state file: ${(err as Error).message}`);
  }
}
