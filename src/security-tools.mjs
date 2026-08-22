import path from 'node:path';

const DEFAULT_TOOL_ROOT = '/Users/unevil-warden-scallion-princess-no-rollback/.local/share/canarynorth-security-tools';

// ELI5: CanaryNorth is the grown-up at the safety desk. These tools are
// different magnifying glasses. This list says what each glass can look at,
// but it never gives one permission to act by itself.
export const SECURITY_TOOLS = Object.freeze([
  // Trivy is a house inspector. It looks for unsafe building plans, broken
  // dependency parts, and keys accidentally left on the floor.
  { id: 'trivy', name: 'Trivy', kind: 'passive-scanner', source: 'aquasecurity/trivy', purpose: 'local files, dependencies, IaC, and secret patterns', binary: 'trivy', localOnly: true, networkValidation: false },
  // TruffleHog is a sniffer dog. It can search old boxes too, including Git
  // history, for things that look like accidentally dropped keys.
  { id: 'trufflehog', name: 'TruffleHog', kind: 'passive-scanner', source: 'trufflesecurity/trufflehog', purpose: 'local filesystem and Git history secret candidates', binary: 'trufflehog', localOnly: true, networkValidation: false },
  // These helpers recognize secret-shaped mistakes in web frameworks.
  { id: 'badsecrets', name: 'badsecrets', kind: 'library-detector', source: 'blacklanternsecurity/badsecrets', purpose: 'framework-aware weak-secret detection', localOnly: true, networkValidation: false },
  { id: 'crapsecrets', name: 'crapsecrets', kind: 'library-detector', source: 'irsdl/crapsecrets', purpose: 'web-framework secret detection research', localOnly: true, networkValidation: false },
  // This is a picture book of known key shapes. We review its pages before
  // using them, rather than trusting every pattern automatically.
  { id: 'secrets-patterns-db', name: 'Secrets Patterns DB', kind: 'rule-corpus', source: 'mazen160/secrets-patterns-db', purpose: 'reviewed pattern-source input', localOnly: true, networkValidation: false },
  // These next tools could touch a real service or token. They are kept behind
  // the extra grown-up locks in authorizeSecurityTool below.
  { id: 'nuclei', name: 'Nuclei templates', kind: 'active-validator', source: 'projectdiscovery/nuclei-templates', purpose: 'owned-target validation only', binary: 'nuclei', localOnly: false, networkValidation: true },
  { id: 'keyhacks', name: 'Keyhacks', kind: 'manual-validation-playbook', source: 'streaak/keyhacks', purpose: 'human-reviewed provider validation guidance', localOnly: false, networkValidation: true },
  // KeyFinder only observes what an approved browser page already shows.
  { id: 'keyfinder', name: 'KeyFinder', kind: 'browser-extension', source: 'momenbasel/KeyFinder', purpose: 'passive browser candidate discovery', localOnly: true, networkValidation: false },
  // SignSaboteur is for testing toy tokens in an owned Burp Suite lab.
  { id: 'sign-saboteur', name: 'SignSaboteur', kind: 'burp-extension', source: 'd0ge/sign-saboteur', purpose: 'owned-lab signed-token integrity testing', localOnly: false, networkValidation: true }
]);

export function securityToolRoot(root = process.env.CANARYNORTH_SECURITY_TOOL_ROOT || DEFAULT_TOOL_ROOT) {
  return path.resolve(root);
}

export function getSecurityTool(id, { root } = {}) {
  const tool = SECURITY_TOOLS.find((item) => item.id === id);
  if (!tool) return null;
  const toolRoot = securityToolRoot(root);
  return Object.freeze({ ...tool, ...(tool.binary ? { command: path.join(toolRoot, 'bin', tool.binary) } : {}), sourcePath: path.join(toolRoot, 'sources', tool.source.split('/').at(-1)) });
}

export function listSecurityTools(options = {}) {
  return SECURITY_TOOLS.map(({ id }) => getSecurityTool(id, options));
}

export function authorizeSecurityTool({ toolId, mode, localRootConfined = false, rawOutputStored = false, networkValidationRequested = false, humanApproved = false, ownedTarget = false, validatorAllowlisted = false, rateWithinBudget = false } = {}) {
  const tool = getSecurityTool(toolId);
  if (!tool) return { allowed: false, reasonCode: 'security-tool-unknown' };
  if (rawOutputStored !== false) return { allowed: false, reasonCode: 'security-tool-raw-output-forbidden' };
  if (tool.kind === 'passive-scanner' || tool.kind === 'library-detector' || tool.kind === 'rule-corpus' || tool.kind === 'browser-extension') {
    // Passive means: look only inside the named local toy box. No raw clues
    // leave the box, and no internet doorbell is pressed.
    if (mode !== 'local-passive' || !localRootConfined || networkValidationRequested) return { allowed: false, reasonCode: 'security-tool-passive-boundary-required' };
    return { allowed: true, reasonCode: 'security-tool-local-passive-approved', executionStatus: 'not-run' };
  }
  if (mode !== 'owned-active') return { allowed: false, reasonCode: 'security-tool-active-mode-required' };
  // Active means: the tool might ring a real doorbell. We require a person,
  // a door we own, an approved bell, and a small knocking budget.
  if (!humanApproved) return { allowed: false, reasonCode: 'security-tool-human-approval-required' };
  if (!ownedTarget) return { allowed: false, reasonCode: 'security-tool-owned-target-required' };
  if (!validatorAllowlisted) return { allowed: false, reasonCode: 'security-tool-validator-not-allowlisted' };
  if (!rateWithinBudget) return { allowed: false, reasonCode: 'security-tool-rate-budget-required' };
  return { allowed: true, reasonCode: 'security-tool-owned-active-approved', executionStatus: 'not-run' };
}
