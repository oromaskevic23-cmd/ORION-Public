/** Independent structural/integrity checker for ORION advisory receipts.
 * Recomputable hashes are NOT authenticated signatures or durable Audit Ledger proof.
 */
import {createHash} from 'node:crypto';
const H=/^[a-f0-9]{64}$/;
const hash=x=>createHash('sha256').update(x).digest('hex');
function gate(x,code){if(!x)throw new Error(code);}
function exact(x,keys){return x&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype && Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));}
const REPORT=['schema','mission_id','report_status','claims','human_review_required',
 'truth_verified','execution','task_dispatch','approval','release','persistence',
 'global_orchestrator','report_sha256','audit_last_sha256'];
const CLAIM=['claim_id','status','independent_domain_count','evidence_reference_count',
 'evidence_verified','domain_positions','review_question'];
const POS=['domain_id','agent_id','stance','summary_sha256','payload_sha256','evidence_sha256'];
export function verifyOrionReport(r){
 gate(exact(r,REPORT),'ORION_REPORT_SCHEMA_DENIED');
 gate(r.schema==='imperial_orion_advisory_report_v1'&&
  /^MISSION-[A-Z0-9_-]{6,48}$/.test(r.mission_id)&&
  ['ADVISORY_ONLY','NO_SUBMISSIONS'].includes(r.report_status),
  'ORION_REPORT_VERSION_DENIED');
 gate(Array.isArray(r.claims)&&r.claims.length<=2048&&
  r.human_review_required===true&&r.truth_verified===false&&
  r.execution==='DENIED'&&r.task_dispatch==='DENIED'&&
  r.approval==='NOT_GRANTED'&&r.release==='DENIED'&&
  r.persistence==='IN_MEMORY_ONLY'&&r.global_orchestrator===false,
  'ORION_REPORT_PRIVILEGE_DRIFT');
 gate((r.claims.length===0)===(r.report_status==='NO_SUBMISSIONS'),
  'ORION_REPORT_STATUS_DRIFT');
 let prev='';
 for(const claim of r.claims){
  gate(exact(claim,CLAIM)&&/^CLAIM-[A-Z0-9_-]{3,60}$/.test(claim.claim_id)&&
   claim.claim_id>prev,'ORION_REPORT_CLAIM_ORDER');
  prev=claim.claim_id;
  gate(Array.isArray(claim.domain_positions)&&claim.domain_positions.length>=1&&
   claim.domain_positions.length<=32&&claim.evidence_verified===false,
   'ORION_REPORT_EVIDENCE_DENIED');
  const seenDomains=new Set(),seenAgents=new Set(),stances=new Set();
  let count=0,last='';
  for(const p of claim.domain_positions){
   gate(exact(p,POS)&&/^DOMAIN-[A-Z0-9_-]{3,40}$/.test(p.domain_id)&&
    /^NCA-[0-9]{12,13}$/.test(p.agent_id)&&
    ['FOR','AGAINST','UNSURE'].includes(p.stance)&&
    p.domain_id>last&&!seenDomains.has(p.domain_id)&&!seenAgents.has(p.agent_id)&&
    H.test(p.summary_sha256)&&H.test(p.payload_sha256)&&
    Array.isArray(p.evidence_sha256)&&p.evidence_sha256.length>=1&&
    p.evidence_sha256.length<=5&&p.evidence_sha256.every(x=>H.test(x)),
    'ORION_REPORT_SOURCE_DENIED');
   last=p.domain_id;seenDomains.add(p.domain_id);seenAgents.add(p.agent_id);
   stances.add(p.stance);count+=p.evidence_sha256.length;
  }
  const conflict=stances.has('FOR')&&stances.has('AGAINST');
  const status=conflict?'CONTRADICTION_NEEDS_REVIEW':seenDomains.size<2?
   'INSUFFICIENT_INDEPENDENT_DOMAINS':'UNCONTESTED_SIGNED_SUBMISSIONS';
  gate(claim.independent_domain_count===seenDomains.size&&
   claim.evidence_reference_count===count&&claim.status===status&&
   typeof claim.review_question==='string'&&claim.review_question.length>0,
   'ORION_REPORT_CLASSIFICATION_DRIFT');
 }
 const unsigned=Object.fromEntries(REPORT.filter(k=>k!=='report_sha256'&&
  k!=='audit_last_sha256').map(k=>[k,r[k]]));
 gate(H.test(r.report_sha256)&&hash(JSON.stringify(unsigned))===r.report_sha256&&
  H.test(r.audit_last_sha256),'ORION_REPORT_HASH_MISMATCH');
 return {verified:true,scope:'SELF_CONSISTENCY_ONLY',
  signed_by_owner:false,evidence_truth_verified:false,execution:'DENIED'};
}
const AUDIT=['schema','accepted_records','trusted_domains','halted','events',
 'audit_last_sha256','persistence','execution','production'];
const EVENT=['sequence','action','previous_sha256','entry_sha256'];
export function verifyOrionAudit(snapshot){
 gate(exact(snapshot,AUDIT)&&snapshot.schema==='imperial_orion_audit_v1'&&
  Number.isSafeInteger(snapshot.accepted_records)&&
  Number.isSafeInteger(snapshot.trusted_domains)&&
  snapshot.trusted_domains>=2&&snapshot.trusted_domains<=32&&
  typeof snapshot.halted==='boolean'&&Array.isArray(snapshot.events)&&
  snapshot.events.length<=4096&&snapshot.persistence==='IN_MEMORY_ONLY'&&
  snapshot.execution==='DENIED'&&snapshot.production==='DENIED',
  'ORION_AUDIT_SCHEMA_DENIED');
 let previous='0'.repeat(64),accepted=0;
 for(let i=0;i<snapshot.events.length;i++){
  const e=snapshot.events[i];
  gate(exact(e,EVENT)&&e.sequence===i+1&&
   ['ACCEPTED_SIGNED_ADVISORY','REJECTED_ORION_SUBMISSION','OWNER_KILL_SWITCH'].includes(e.action)&&
   e.previous_sha256===previous,'ORION_AUDIT_CHAIN_DENIED');
  const canonical={sequence:e.sequence,action:e.action,previous_sha256:e.previous_sha256};
  previous=hash(JSON.stringify(canonical));
  gate(e.entry_sha256===previous,'ORION_AUDIT_HASH_DENIED');
  if(e.action==='ACCEPTED_SIGNED_ADVISORY')accepted++;
 }
 gate(snapshot.audit_last_sha256===previous&&snapshot.accepted_records===accepted,
  'ORION_AUDIT_HEAD_MISMATCH');
 return {verified:true,scope:'SELF_CONSISTENCY_ONLY',
  durable:false,authenticated:false,execution:'DENIED'};
}
