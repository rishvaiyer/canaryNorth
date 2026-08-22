import path from 'node:path';

import { runPassiveScan } from '../src/passive-scanner.mjs';

const toolId = process.argv[2];
const targetPath = process.env.CANARYNORTH_SCAN_TARGET;
const allowedRoot = process.env.CANARYNORTH_SCAN_ROOT;

if (!['trivy', 'trufflehog'].includes(toolId)) {
  throw new Error('passive-scan-tool-must-be-trivy-or-trufflehog');
}
if (process.env.CANARYNORTH_SCAN_CONFIRM !== 'LOCAL_PASSIVE_ONLY') {
  throw new Error('passive-scan-confirmation-required');
}
if (!targetPath || !allowedRoot) {
  throw new Error('passive-scan-target-and-root-required');
}

const report = await runPassiveScan(toolId, path.resolve(targetPath), {
  allowedRoot: path.resolve(allowedRoot)
});

// Never print raw scanner findings. The returned report has counts only.
process.stdout.write(`${JSON.stringify(report)}\n`);
