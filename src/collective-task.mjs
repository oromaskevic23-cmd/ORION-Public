import { aggregateCollectiveDecision } from './collective-decision.mjs';
import { validateFederationEnvelope } from './federation-envelope.mjs';
// Bounded local integration exercise, not a production agent runtime.
export function runCollectiveTask({task_id, orchestrator_id, submissions}) {
  if (!Array.isArray(submissions) || submissions.length < 2 || submissions.length > 100) throw new RangeError('2..100 submissions required');
  const requestIds = new Set();
  const proposals = submissions.map(({envelope,proposal}) => {
    const e = validateFederationEnvelope(envelope);
    if (e.task_id !== task_id || e.orchestrator_id !== orchestrator_id) throw new Error('federation scope mismatch');
    if (requestIds.has(e.request_id)) throw new Error('duplicate request_id');
    requestIds.add(e.request_id);
    if (!proposal || proposal.agent_id !== e.source_agent_id) throw new Error('agent identity mismatch');
    return proposal;
  });
  const decision = aggregateCollectiveDecision({proposals});
  return Object.freeze({task_id,orchestrator_id,decision,live_agents_verified:false,execution_authorized:false});
}
