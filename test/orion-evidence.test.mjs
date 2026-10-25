import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {OrionAdvisory,ORION_SCHEMA,canonicalAdvisoryBytes} from '../src/orion-advisory.mjs';
import {verifyOrionReport,verifyOrionAudit} from '../src/orion-evidence.mjs';
const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
const names=['DOMAIN-ALPHA','DOMAIN-BRAVO'];
function engine(){
 const o=new OrionAdvisory({trustedDomainPublicKeys:keys.map((key,i)=>({domain_id:names[i],public_key:key.publicKey}))});
 const now=Date.now();
 for(let i=0;i<2;i++){
  const claims={schema:ORION_SCHEMA,mission_id:'MISSION-ORION-EVIDENCE-001',domain_id:names[i],
   agent_id:'NCA-'+String(i+1).padStart(12,'0'),claim_id:'CLAIM-SECURITY-001',
   stance:i?'AGAINST':'FOR',evidence_sha256:[createHash('sha256').update('synthetic-'+i).digest('hex')],
   summary:'Synthetic evidence',issued_at:now-1000,expires_at:now+30000,
   nonce:String(i+1).padStart(32,'0')};
  o.submit({claims,signature:sign(null,canonicalAdvisoryBytes(claims),keys[i].privateKey).toString('base64url')});
 }
 return o;
}
test('independent verifier accepts in-memory report structure',()=>{
 const v=verifyOrionReport(engine().report('MISSION-ORION-EVIDENCE-001'));
 assert.equal(v.scope,'SELF_CONSISTENCY_ONLY');assert.equal(v.signed_by_owner,false);
});
test('audit verifier checks in-memory event hash chain',()=>{
 const v=verifyOrionAudit(engine().snapshot());
 assert.equal(v.verified,true);assert.equal(v.authenticated,false);assert.equal(v.durable,false);
});
test('tampered advisory never gains release permission',()=>{
 const r=engine().report('MISSION-ORION-EVIDENCE-001');r.release='APPROVED';
 assert.throws(()=>verifyOrionReport(r),/ORION_REPORT_PRIVILEGE_DRIFT/);
});
test('altered stance breaks report classification and digest',()=>{
 const r=engine().report('MISSION-ORION-EVIDENCE-001');
 r.claims[0].domain_positions[1].stance='FOR';
 assert.throws(()=>verifyOrionReport(r),/ORION_REPORT_CLASSIFICATION_DRIFT|ORION_REPORT_HASH_MISMATCH/);
});
test('fabricated evidence hash is rejected unless report recomputed',()=>{
 const r=engine().report('MISSION-ORION-EVIDENCE-001');
 r.claims[0].domain_positions[0].evidence_sha256[0]='a'.repeat(64);
 assert.throws(()=>verifyOrionReport(r),/ORION_REPORT_HASH_MISMATCH/);
});
test('audit tampering in action or event order detected',()=>{
 const a=engine().snapshot();a.events[0].action='OWNER_KILL_SWITCH';
 assert.throws(()=>verifyOrionAudit(a),/ORION_AUDIT_HASH_DENIED/);
 const b=engine().snapshot();b.events[1].sequence=99;
 assert.throws(()=>verifyOrionAudit(b),/ORION_AUDIT_CHAIN_DENIED/);
});
test('false accepted count denied',()=>{
 const a=engine().snapshot();a.accepted_records++;
 assert.throws(()=>verifyOrionAudit(a),/ORION_AUDIT_HEAD_MISMATCH/);
});


test('codepoint sorting remains verifier-compatible across multiple claim keys',()=>{
 const o=engine(),now=Date.now();
 for(const claim_id of ['CLAIM-A__001','CLAIM-A--001']){
  for(let i=0;i<2;i++){
   const claims={schema:ORION_SCHEMA,mission_id:'MISSION-ORION-EVIDENCE-001',
    domain_id:names[i],agent_id:'NCA-'+String(i+1).padStart(12,'0'),
    claim_id,stance:'UNSURE',evidence_sha256:[createHash('sha256').update(claim_id+i).digest('hex')],
    summary:'Additional synthetic claim',issued_at:now-1000,expires_at:now+30000,
    nonce:(10+i+(claim_id.includes('__')?0:3)).toString(16).padStart(32,'0')};
   o.submit({claims,signature:sign(null,canonicalAdvisoryBytes(claims),keys[i].privateKey).toString('base64url')});
  }
 }
 const report=o.report('MISSION-ORION-EVIDENCE-001');
 assert.equal(report.claims.length,3);
 assert.equal(verifyOrionReport(report).verified,true);
});
