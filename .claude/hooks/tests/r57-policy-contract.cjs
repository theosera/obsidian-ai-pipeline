'use strict';
// Declarative policy contract only. No filesystem/backend probe or Hook result
// enters qualification or expectation derivation. Matching is a separate step.
const crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
const json = value => JSON.stringify(value);
const IDS = Object.freeze(['R29SW19', 'R29SW20', 'R29SW21', 'R29SW22', 'R29SW23', 'R29SW32', 'R29SW34', 'R29SW35', 'R29SW40', 'R29SW44', 'R29SW45']);
const ORIGINAL = '450e94994846d221d3056b1580822b513d6f87c5f086f14b7b95389c85a46b75';
const R54 = 'f7760a0bc01b10caf7b302ac3e0686c1cd762d219041568f054f8816c2f95d90';
const EG = 'block-secret-egress.cjs';
const PREFIX = '[判断不能] ';
const SET = { expect: 'deny', expectedOwnEG: 'UNKNOWN', denyBy: EG, expectReasonPrefixes: { [EG]: PREFIX } };
const ASSERTIONS = new Set(['expect', 'expectedOwnEG', 'expectedOwnSG', 'expectedOwnAG', 'denyBy', 'allowBy', 'allowByEG', 'expectReasonPrefixes']);
const input = c => Object.fromEntries(Object.entries(c).filter(([key]) => !ASSERTIONS.has(key)));
const need = (ok, message) => { if (!ok) throw Error(message); };

function createPolicyContract(cases, ledger, r54LedgerBytes) {
  need(Array.isArray(cases) && cases.length === 8696 && hash(cases) === ORIGINAL, 'R57 original 8696 definitions drift');
  need(Buffer.isBuffer(r54LedgerBytes) && hash(r54LedgerBytes) === R54, 'R57 exact immutable R54 ledger bytes required');
  const backend = JSON.parse(r54LedgerBytes);
  need(backend.entries.length === 654 && backend.baselineDefinitionsSHA256 === ORIGINAL, 'R57 R54 profile identity mismatch');
  need(ledger.schema === 'R57_REQUIRED_SUDO_POLICY_CONTRACT_V1' && ledger.contractID === 'R57_REQUIRED_SUDO_POLICY_ROOT_UNQUALIFIED_V1' &&
    ledger.baselineCount === 8696 && ledger.baselineDefinitionsSHA256 === ORIGINAL && ledger.r54BackendLedgerSHA256 === R54 &&
    ledger.r54BackendDeclarationCount === 654 && ledger.reviewReference?.commentID === 4317915874 &&
    ledger.reviewReference.reviewID === 5576618827 && ledger.reviewReference.publicHead === 'c1c5bd9dcccd0a42c769f473d5328cf1b651708d' &&
    ledger.reviewReference.bodySHA256 === '152be833275462b75ac10a2860027c666f486b919a89f32a4620b89e9fcae0d2', 'R57 policy source contract mismatch');
  need(Array.isArray(ledger.entries) && json(ledger.entries.map(d => d.id)) === json(IDS), 'R57 exact eleven declarations required');
  const byID = new Map(cases.map((c, index) => [c.id, { c, index }]));
  const backendIDs = new Set(backend.entries.map(d => d.id));
  need(byID.size === 8696 && backendIDs.size === 654, 'R57 duplicate original/backend ID');
  const contractID = ledger.contractID;
  const declared = new Map();
  for (const d of ledger.entries) {
    const original = byID.get(d.id);
    need(original && !backendIDs.has(d.id) && !declared.has(d.id) && original.index === d.originalIndex &&
      original.c.expect === 'allow' && original.c.cmd.startsWith('sudo ') &&
      d.kind === 'REQUIRED_SUDO_POLICY_ROOT_UNQUALIFIED' && json(d.setFields) === json(SET) &&
      hash(original.c) === d.originalDefinitionJSONSHA256 && json(original.c) === json(d.originalDefinition) &&
      hash(input(original.c)) === d.originalInputJSONSHA256 && json(input(original.c)) === json(d.originalInput), 'R57 fixed declaration/input/nonoverlap mismatch');
    declared.set(d.id, JSON.parse(json(d)));
  }
  const originalHashes = new Map(cases.map(c => [c.id, hash(c)]));
  function exact(c) { need(byID.has(c.id) && hash(c) === originalHashes.get(c.id), 'R57 original case changed'); }
  return {
    contractID,
    declaredCount: IDS.length,
    qualify(c) {
      exact(c);
      const d = declared.get(c.id);
      return { caseID: c.id, originalCaseSHA256: hash(c), applies: !!d,
        reason: d ? 'required-sudo-policy-root-unqualified' : 'no-r57-policy-declaration',
        source: 'fixed-policy-declaration-only', contractID,
        ...(d ? { originalInputSHA256: d.originalInputJSONSHA256, reviewCommentID: 4317915874 } : {}) };
    },
    effectiveCase(c, r54Expected, q) {
      exact(c);
      need(q.caseID === c.id && q.originalCaseSHA256 === hash(c) && q.applies === declared.has(c.id) &&
        q.source === 'fixed-policy-declaration-only' && q.contractID === contractID, 'R57 qualification/case mismatch');
      if (!q.applies) return r54Expected;
      need(json(r54Expected) === json(c), 'R57 cannot replace a changed R54 expectation');
      return { ...r54Expected, expect: 'deny', expectedOwnEG: 'UNKNOWN', denyBy: EG,
        expectReasonPrefixes: { ...r54Expected.expectReasonPrefixes, [EG]: PREFIX } };
    },
    nonEgressAssertionsMatch(result, originalCase) {
      exact(originalCase);
      // Every declared original expects overall ALLOW, which requires both
      // other hooks ALLOW. Preserve that obligation outside the four changed fields.
      return !declared.has(originalCase.id) || result.ownSG === 'ALLOW' && result.ownAG === 'ALLOW';
    },
    definitionsUnchanged: () => hash(cases) === ORIGINAL,
  };
}
module.exports = { createPolicyContract };
