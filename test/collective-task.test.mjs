import test from 'node:test';
import assert from 'node:assert/strict';
import { runCollectiveTask } from '../src/collective-task.mjs';
const digest='sha256:'+'a'.repeat(64);
const submission=(agent,choice)=>({
 envelope:{schema_version:'orion.federation.v1',task_id:'task1',request_id:'req_'+agent,source_agent_id:agent,orchestrator_id:'astra',operation:'COLLECTIVE_PROPOSAL',payload_digest:digest,created_at:'2026-10-27T12:00:00Z',execution_authorized:false},
 proposal:{agent_id:agent,choice,evidence:[digest]}
});
test('three independent submissions yield provisional decision without execution',()=>{
 const result=runCollectiveTask({task_id:'task1',orchestrator_id:'astra',submissions:[submission('a','ship'),submission('b','ship'),submission('c','hold')]});
 assert.equal(result.decision.choice,'ship');assert.equal(result.decision.status,'PROVISIONAL_CONSENSUS');
 assert.equal(result.execution_authorized,false);assert.equal(result.live_agents_verified,false);
});
test('cross-task submissions fail closed',()=>assert.throws(()=>runCollectiveTask({task_id:'other',orchestrator_id:'astra',submissions:[submission('a','yes'),submission('b','yes')]}),/scope mismatch/));
test('agent spoofing fails closed',()=>{const x=submission('a','yes');x.proposal.agent_id='fake';assert.throws(()=>runCollectiveTask({task_id:'task1',orchestrator_id:'astra',submissions:[x,submission('b','yes')]}),/identity mismatch/)});
test('replayed request id fails closed',()=>{const x=submission('a','yes'),y=submission('b','yes');y.envelope.request_id=x.envelope.request_id;assert.throws(()=>runCollectiveTask({task_id:'task1',orchestrator_id:'astra',submissions:[x,y]}),/duplicate request_id/)});
