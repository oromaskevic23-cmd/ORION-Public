import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateCollectiveDecision } from '../src/collective-decision.mjs';
const hash = 'sha256:' + 'a'.repeat(64);
const p = (agent_id,choice) => ({agent_id,choice,evidence:[hash]});
test('majority provisional and never authorizes execution',()=>{
 const x=aggregateCollectiveDecision({proposals:[p('a','yes'),p('b','yes'),p('c','no')]});
 assert.equal(x.status,'PROVISIONAL_CONSENSUS');assert.equal(x.choice,'yes');assert.equal(x.execution_authorized,false);assert.equal(x.evidence_verified,false);
});
test('tie returns conflict',()=>assert.equal(aggregateCollectiveDecision({proposals:[p('a','yes'),p('b','no')]}).status,'CONFLICT'));
test('plurality without majority returns no consensus',()=>assert.equal(aggregateCollectiveDecision({proposals:[p('a','a'),p('b','b'),p('c','c')]}).status,'NO_CONSENSUS'));
test('duplicate identity rejected',()=>assert.throws(()=>aggregateCollectiveDecision({proposals:[p('a','yes'),p('a','yes')]}),/duplicate/));
test('missing evidence rejected',()=>assert.throws(()=>aggregateCollectiveDecision({proposals:[{agent_id:'a',choice:'yes',evidence:[]},p('b','yes')]}),/evidence/));
test('too many proposals rejected',()=>assert.throws(()=>aggregateCollectiveDecision({proposals:Array.from({length:101},(_,i)=>p('a'+i,'yes'))}),/100/));
