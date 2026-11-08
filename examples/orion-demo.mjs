import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {OrionAdvisory,canonicalAdvisoryBytes,ORION_SCHEMA} from '../src/orion-advisory.mjs';
const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
const names=['DOMAIN-ALPHA','DOMAIN-BRAVO'];
const instance=new OrionAdvisory({trustedDomainPublicKeys:keys.map((k,i)=>({domain_id:names[i],public_key:k.publicKey}))});
const now=Date.now();
for(let i=0;i<2;i++){
 const claims={schema:ORION_SCHEMA,mission_id:'MISSION-ORION-DEMO-0001',
  domain_id:names[i],agent_id:'NCA-'+String(i+1).padStart(12,'0'),
  claim_id:'CLAIM-BOUNDARY-001',stance:i?'AGAINST':'FOR',
  evidence_sha256:[createHash('sha256').update('fictional-evidence-'+i).digest('hex')],
  summary:'Synthetic claim. No real-world assertion or evidence validation.',
  issued_at:now-1000,expires_at:now+60000,
  nonce:(i+1).toString(16).padStart(32,'0')};
 instance.submit({claims,signature:sign(null,canonicalAdvisoryBytes(claims),keys[i].privateKey).toString('base64url')});
}
const report=instance.report('MISSION-ORION-DEMO-0001');
if(report.claims[0]?.status!=='CONTRADICTION_NEEDS_REVIEW'||report.execution!=='DENIED')throw Error('DEMO_FAILED');
console.log(JSON.stringify({demo:'SYNTHETIC_OFFLINE_ONLY',report},null,2));
