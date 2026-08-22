import { spawn as defaultSpawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

import { authorizeSecurityTool, getSecurityTool } from './security-tools.mjs';

function outside(root, target) {
  const relative = path.relative(root, target);
  return relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
}

export async function resolvePassiveScanTarget(targetPath, allowedRoot) {
  // ELI5: a scan may look only inside the toy box the person named. A shortcut
  // pointing outside the box does not fool this realpath check.
  const root = await fs.realpath(path.resolve(allowedRoot));
  const target = await fs.realpath(path.resolve(targetPath));
  const stats = await fs.stat(target);
  if (!stats.isDirectory() || outside(root, target)) throw new Error('passive-scan-target-outside-approved-root');
  return { root, target };
}

export function buildPassiveScanCommand(toolId, targetPath, options = {}) {
  const authorization = authorizeSecurityTool({ toolId, mode: 'local-passive', localRootConfined: true, rawOutputStored: false, networkValidationRequested: false });
  if (!authorization.allowed) throw new Error(authorization.reasonCode);
  const tool = getSecurityTool(toolId, options);
  if (!tool?.command) throw new Error('passive-scanner-command-missing');
  if (toolId === 'trivy') return { command: tool.command, args: ['fs', '--scanners', 'secret,misconfig', '--format', 'json', '--quiet', '--skip-db-update', '--skip-java-db-update', '--offline', targetPath] };
  if (toolId === 'trufflehog') return { command: tool.command, args: ['filesystem', '--directory', targetPath, '--json', '--no-verification'] };
  throw new Error('passive-scanner-not-supported');
}

export function redactScannerOutput(toolId, output = '') {
  // The scanner may see a real-looking key. CanaryNorth keeps only the number
  // of clues, like saying "three things need review," never the key itself.
  if (typeof output !== 'string') throw new Error('scanner-output-invalid');
  if (toolId === 'trivy') {
    const parsed = JSON.parse(output || '{"Results":[]}');
    const findings = (parsed.Results || []).reduce((total, result) => total + (result.Secrets?.length || 0) + (result.Misconfigurations?.length || 0), 0);
    return Object.freeze({ source: 'trivy', executionStatus: 'completed', findingCount: findings, rawOutputStored: false, evidence: '[redacted]' });
  }
  if (toolId === 'trufflehog') {
    const findings = output.split('\n').filter(Boolean).length;
    return Object.freeze({ source: 'trufflehog', executionStatus: 'completed', findingCount: findings, rawOutputStored: false, evidence: '[redacted]' });
  }
  throw new Error('passive-scanner-not-supported');
}

function run(command, args, { spawnImpl = defaultSpawn, timeoutMs = 30_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawnImpl(command, args, { stdio: ['ignore', 'pipe', 'ignore'] });
    let output = '';
    let done = false;
    const finish = (result) => { if (!done) { done = true; clearTimeout(timer); resolve(result); } };
    child.stdout?.on('data', (chunk) => { if (output.length < 5_000_000) output += chunk; });
    child.once('error', () => finish({ executionStatus: 'error' }));
    child.once('exit', (code) => finish({ executionStatus: code === 0 ? 'completed' : 'error', output }));
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} finish({ executionStatus: 'timed-out' }); }, timeoutMs);
  });
}

export async function runPassiveScan(toolId, targetPath, { allowedRoot, spawnImpl, timeoutMs, ...options } = {}) {
  // This is intentionally a local-only helper. It does not validate a found
  // key against a provider, contact a target, or save raw scanner output.
  const { target } = await resolvePassiveScanTarget(targetPath, allowedRoot);
  const { command, args } = buildPassiveScanCommand(toolId, target, options);
  const result = await run(command, args, { spawnImpl, timeoutMs });
  if (result.executionStatus !== 'completed') return Object.freeze({ source: toolId, executionStatus: result.executionStatus, findingCount: 0, rawOutputStored: false, evidence: '[redacted]' });
  return redactScannerOutput(toolId, result.output);
}
