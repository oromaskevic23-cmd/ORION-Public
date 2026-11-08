import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {verifyCollectiveTask} from '../src/verified-collective-task.mjs';
const digest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
const canonical=e=>JSON.stringify({schema_version:e.schema_version,task_id:e.task_id,request_id:e.request_id,source_agent_id:e.source_agent_id,orchestrator_id:e.orchestrator_id,operation:e.operation,payload_digest:e.payload_digest,created_at:e.created_at,execution_authorized:e.execution_authorized});
const fixture=()=>{
 const publicKeys=new Map(),evidenceStore=new Map(),submissions=[];
 for(const [id,choice] of [['nca1','ship'],['nca2','ship'],['nca3','hold']]){
  const keys=generateKeyPairSync('ed25519');publicKeys.set(id,keys.publicKey);
  const bytes=Buffer.from('evidence-'+id);const ref=digest(bytes);evidenceStore.set(ref,bytes);
  const proposal={agent_id:id,choice,evidence:[ref]};
  const envelope={schema_version:'orion.federation.v1',task_id:'task1',request_id:'req_'+id,source_agent_id:id,orchestrator_id:'astra',operation:'COLLECTIVE_PROPOSAL',payload_digest:digest(Buffer.from(JSON.stringify(proposal))),created_at:'2026-10-27T12:00:00Z',execution_authorized:false};
  submissions.push({envelope,proposal,signature:sign(null,Buffer.from(canonical(envelope)),keys.privateKey).toString('hex')});
 }
 return {task_id:'task1',orchestrator_id:'astra',submissions,publicKeys,evidenceStore};
};
test('three signed NCA proposals reach evidence-verified provisional consensus',()=>{
 const r=verifyCollectiveTask(fixture());
 assert.equal(r.decision.choice,'ship');assert.equal(r.decision.evidence_verified,true);assert.equal(r.signatures_verified,true);assert.equal(r.execution_authorized,false);assert.equal(r.live_agents_verified,false);
});
test('tampered signature fails closed',()=>{const f=fixture();f.submissions[0].signature='0'.repeat(128);assert.throws(()=>verifyCollectiveTask(f),/invalid signature/)});
test('tampered evidence fails closed',()=>{const f=fixture();const ref=f.submissions[0].proposal.evidence[0];f.evidenceStore.set(ref,Buffer.from('tampered'));assert.throws(()=>verifyCollectiveTask(f),/digest mismatch/)});
test('tampered proposal fails closed',()=>{const f=fixture();f.submissions[0].proposal.choice='hold';assert.throws(()=>verifyCollectiveTask(f),/payload mismatch/)});
