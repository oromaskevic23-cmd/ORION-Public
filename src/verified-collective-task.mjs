import { createHash, verify } from 'node:crypto';
import { runCollectiveTask } from './collective-task.mjs';
// Staging-only verification adapter. Public keys and immutable evidence are supplied by trusted caller.
// It never executes work, grants authority, or verifies a live NCA connection.
const canonical = (e) => JSON.stringify({
 schema_version:e.schema_version, task_id:e.task_id, request_id:e.request_id,
 source_agent_id:e.source_agent_id, orchestrator_id:e.orchestrator_id,
 operation:e.operation, payload_digest:e.payload_digest, created_at:e.created_at,
 execution_authorized:e.execution_authorized
});
export function verifyCollectiveTask({task_id,orchestrator_id,submissions,publicKeys,evidenceStore}) {
 if (!(publicKeys instanceof Map) || !(evidenceStore instanceof Map)) throw new TypeError('trusted publicKeys and evidenceStore Maps required');
 if (!Array.isArray(submissions)) throw new TypeError('submissions required');
 const verified = submissions.map(s => {
  if (!s || !s.envelope || !s.proposal) throw new TypeError('submission required');
  const {envelope:e,proposal:p,signature} = s;
  const key=publicKeys.get(e.source_agent_id);
  if (!key || typeof signature !== 'string' || !/^[a-f0-9]{128}$/.test(signature)) throw new Error('untrusted agent signature');
  if (!verify(null,Buffer.from(canonical(e)),key,Buffer.from(signature,'hex'))) throw new Error('invalid signature');
  if (!Array.isArray(p.evidence)) throw new Error('evidence missing');
  for (const ref of p.evidence) {
   const bytes=evidenceStore.get(ref);
   if (!Buffer.isBuffer(bytes) || 'sha256:'+createHash('sha256').update(bytes).digest('hex') !== ref) throw new Error('evidence digest mismatch');
  }
  const payload=Buffer.from(JSON.stringify(p));
  if ('sha256:'+createHash('sha256').update(payload).digest('hex') !== e.payload_digest) throw new Error('proposal payload mismatch');
  return {envelope:e,proposal:p};
 });
 const result=runCollectiveTask({task_id,orchestrator_id,submissions:verified});
 return Object.freeze({...result,decision:Object.freeze({...result.decision,evidence_verified:true}),signatures_verified:true,live_agents_verified:false,execution_authorized:false});
}
