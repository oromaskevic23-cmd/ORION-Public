// ORION Sprint 006: deterministic, bounded collective decision reference.
// No model inference, network calls, side effects or production dispatch.
export function aggregateCollectiveDecision(input) {
  if (!input || typeof input !== 'object' || !Array.isArray(input.proposals)) throw new TypeError('proposals required');
  if (input.proposals.length < 2 || input.proposals.length > 100) throw new RangeError('2..100 proposals required');
  const seen = new Set();
  const tally = new Map();
  for (const p of input.proposals) {
    if (!p || typeof p !== 'object' || typeof p.agent_id !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(p.agent_id)) throw new TypeError('invalid agent_id');
    if (seen.has(p.agent_id)) throw new Error('duplicate agent_id');
    seen.add(p.agent_id);
    if (typeof p.choice !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(p.choice)) throw new TypeError('invalid choice');
    if (!Array.isArray(p.evidence) || p.evidence.length === 0 || p.evidence.length > 20 || !p.evidence.every(x => typeof x === 'string' && /^sha256:[a-f0-9]{64}$/.test(x))) throw new TypeError('invalid evidence references');
    tally.set(p.choice, (tally.get(p.choice) ?? 0) + 1);
  }
  const ranked = [...tally].sort((a,b) => b[1]-a[1] || a[0].localeCompare(b[0]));
  const tied = ranked.length > 1 && ranked[0][1] === ranked[1][1];
  const votes = ranked[0][1];
  const quorum = votes > input.proposals.length / 2;
  return Object.freeze({
    status: tied ? 'CONFLICT' : quorum ? 'PROVISIONAL_CONSENSUS' : 'NO_CONSENSUS',
    choice: tied || !quorum ? null : ranked[0][0],
    votes,
    total: input.proposals.length,
    tally: Object.fromEntries(ranked),
    evidence_verified: false,
    execution_authorized: false
  });
}
