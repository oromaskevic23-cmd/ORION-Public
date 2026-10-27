import test from 'node:test';
import assert from 'node:assert/strict';
import {deliberate} from '../src/orion-enterprise.mjs';
const agent=(id,vote='RECOMMEND')=>({agentId:id,passport:{agentId:id,status:'ACTIVE'},
 capabilities:['ORION_DELIBERATE'],vote,reason:'Independent reasoned assessment'});
const base=()=>({taskId:'ORION-001',question:'Should this proposal proceed to owner review?',participants:[agent('agent-one'),agent('agent-two')]});
test('quorum yields recommendation but never execution authority',()=>{
 const a=deliberate(base()),b=deliberate(base());
 assert.equal(a.outcome,'RECOMMEND');
 assert.equal(a.executionAuthorized,false);
 assert.equal(a.approval,'OWNER_REQUIRED');
 assert.equal(a.evidenceSha256,b.evidenceSha256);
});
test('split vote fails closed',()=>{
 const r=deliberate({...base(),participants:[agent('agent-one'),agent('agent-two','ESCALATE')]});
 assert.equal(r.outcome,'NO_CONSENSUS');
});
test('duplicate agent identity is denied',()=>assert.throws(
 ()=>deliberate({...base(),participants:[agent('agent-one'),agent('agent-one')]}),
 /AGENT_IDENTITY_OR_CAPABILITY_DENIED/));
test('unapproved passport is denied',()=>assert.throws(
 ()=>deliberate({...base(),participants:[agent('agent-one'),{...agent('agent-two'),passport:{agentId:'agent-two',status:'REVOKED'}}]}),
 /AGENT_IDENTITY_OR_CAPABILITY_DENIED/));
test('capability absent is denied',()=>assert.throws(
 ()=>deliberate({...base(),participants:[agent('agent-one'),{...agent('agent-two'),capabilities:[]}]}),
 /AGENT_IDENTITY_OR_CAPABILITY_DENIED/));
test('insufficient quorum is rejected',()=>assert.throws(
 ()=>deliberate({...base(),minimumQuorum:3}),/INVALID_COUNCIL_REQUEST/));
