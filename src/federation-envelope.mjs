// ORION federation envelope validation. Pure function: no dispatch or authority.
const ID = /^[A-Za-z0-9_-]{1,80}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
export function validateFederationEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new TypeError('envelope required');
  if (envelope.schema_version !== 'orion.federation.v1') throw new TypeError('schema version');
  for (const k of ['task_id','request_id','source_agent_id','orchestrator_id']) {
    if (typeof envelope[k] !== 'string' || !ID.test(envelope[k])) throw new TypeError(k);
  }
  if (envelope.operation !== 'COLLECTIVE_PROPOSAL') throw new Error('unsupported operation');
  if (typeof envelope.payload_digest !== 'string' || !DIGEST.test(envelope.payload_digest)) throw new TypeError('payload_digest');
  if (typeof envelope.created_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(envelope.created_at) || !Number.isFinite(Date.parse(envelope.created_at))) throw new TypeError('created_at');
  if (envelope.execution_authorized !== false) throw new Error('execution forbidden');
  return Object.freeze({
    schema_version:envelope.schema_version,
    task_id:envelope.task_id,
    request_id:envelope.request_id,
    source_agent_id:envelope.source_agent_id,
    orchestrator_id:envelope.orchestrator_id,
    operation:envelope.operation,
    payload_digest:envelope.payload_digest,
    created_at:envelope.created_at,
    execution_authorized:false,
    signature_verified:false
  });
}
