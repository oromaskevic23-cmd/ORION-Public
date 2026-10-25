/**
 * ORION — Federated Collective Intelligence / Read-only Advisory v0.1.
 * Public first-party reference implementation: no execution, no delegation,
 * no global orchestration, no network, no payment or release capability.
 */
import {createHash, createPublicKey, KeyObject, verify} from 'node:crypto';

export const ORION_SCHEMA = 'imperial_orion_advisory_v1';
const CLAIM_KEYS = Object.freeze(['schema','mission_id','domain_id','agent_id','claim_id',
  'stance','evidence_sha256','summary','issued_at','expires_at','nonce']);
const SHA = /^[a-f0-9]{64}$/;
const MISSION = /^MISSION-[A-Z0-9_-]{6,48}$/;
const DOMAIN = /^DOMAIN-[A-Z0-9_-]{3,40}$/;
const AGENT = /^NCA-[0-9]{12,13}$/;
const CLAIM = /^CLAIM-[A-Z0-9_-]{3,60}$/;
const NONCE = /^[a-f0-9]{32,64}$/;
const STANCES = new Set(['FOR','AGAINST','UNSURE']);
const sha256 = x => createHash('sha256').update(x).digest('hex');
function gate(ok, code) {if(!ok) throw new Error(code);}
function plain(x) {return x!==null && typeof x==='object' && !Array.isArray(x) &&
  Object.getPrototypeOf(x)===Object.prototype;}
function exact(x, fields){return plain(x) && Object.keys(x).length===fields.length &&
  fields.every(key=>Object.hasOwn(x,key));}
function canonical(x, fields){return JSON.stringify(Object.fromEntries(fields.map(key=>[key,x[key]])));}
function boundId(id,re){gate(typeof id==='string' && re.test(id),'ORION_INVALID_IDENTIFIER');}
function clone(x){return structuredClone(x);}

export function canonicalAdvisoryBytes(c){
 gate(exact(c,CLAIM_KEYS),'ORION_CLAIM_SCHEMA_DENIED');
 gate(c.schema===ORION_SCHEMA,'ORION_CLAIM_VERSION_DENIED');
 boundId(c.mission_id,MISSION); boundId(c.domain_id,DOMAIN);
 boundId(c.agent_id,AGENT);boundId(c.claim_id,CLAIM);
 gate(STANCES.has(c.stance),'ORION_POSITION_DENIED');
 gate(Array.isArray(c.evidence_sha256) && c.evidence_sha256.length>=1 &&
  c.evidence_sha256.length<=5 && c.evidence_sha256.every(x=>typeof x==='string'&&SHA.test(x)) &&
  new Set(c.evidence_sha256).size===c.evidence_sha256.length,'ORION_EVIDENCE_REF_DENIED');
 gate(typeof c.summary==='string' && c.summary.trim().length>=1 &&
  c.summary.length<=800 && !/[\u0000-\u0008\u000b-\u001f]/.test(c.summary),
  'ORION_SUMMARY_DENIED');
 gate(Number.isSafeInteger(c.issued_at) && Number.isSafeInteger(c.expires_at) &&
  c.issued_at>=0 && c.expires_at>c.issued_at &&
  c.expires_at-c.issued_at<=300000,'ORION_TTL_DENIED');
 gate(typeof c.nonce==='string' && NONCE.test(c.nonce),'ORION_NONCE_DENIED');
 return Buffer.from(canonical(c,CLAIM_KEYS),'utf8');
}
function publicEd25519(candidate){
 try {
  gate((candidate instanceof KeyObject && candidate.type==='public') ||
    (typeof candidate==='string' && candidate.startsWith('-----BEGIN PUBLIC KEY-----')),
    'ORION_KEY_DENIED');
  const k=candidate instanceof KeyObject ? candidate : createPublicKey(candidate);
  gate(k.type==='public' && k.asymmetricKeyType==='ed25519','ORION_KEY_DENIED');
  return k;
 } catch {throw new Error('ORION_KEY_DENIED');}
}

export class OrionAdvisory {
 #keys=new Map();#missions=new Map();#replays=new Set();#audit=[];
 #last='0'.repeat(64);#halted=false;#now;#maxRecords;#accepted=0;
 constructor({trustedDomainPublicKeys,now=()=>Date.now(),maxRecords=256}={}){
  gate(Array.isArray(trustedDomainPublicKeys)&&trustedDomainPublicKeys.length>=2&&
    trustedDomainPublicKeys.length<=32,'ORION_TRUST_REGISTRY_REQUIRED');
  gate(typeof now==='function' && Number.isSafeInteger(maxRecords) &&
    maxRecords>=2 && maxRecords<=2048,'ORION_CONFIGURATION_DENIED');
  const keyFingerprints=new Set();
  for(const item of trustedDomainPublicKeys){
   gate(exact(item,['domain_id','public_key']),'ORION_TRUST_ENTRY_DENIED');
   boundId(item.domain_id,DOMAIN);
   gate(!this.#keys.has(item.domain_id),'ORION_DUPLICATE_TRUST_DOMAIN');
   const key=publicEd25519(item.public_key);
   const fingerprint=sha256(key.export({type:'spki',format:'der'}));
   gate(!keyFingerprints.has(fingerprint),'ORION_DUPLICATE_DOMAIN_KEY');
   keyFingerprints.add(fingerprint);
   this.#keys.set(item.domain_id,key);
  }
  this.#now=now;this.#maxRecords=maxRecords;
 }
 #log(action){
  if(this.#audit.length>=4096){this.#halted=true;throw new Error('ORION_AUDIT_CAPACITY_DENIED');}
  const entry={sequence:this.#audit.length+1,action,previous_sha256:this.#last};
  this.#last=sha256(JSON.stringify(entry));
  this.#audit.push({...entry,entry_sha256:this.#last});
 }
 submit(envelope){
  try {
   gate(!this.#halted,'ORION_KILL_SWITCH_ACTIVE');
   gate(exact(envelope,['claims','signature']),'ORION_SIGNED_ENVELOPE_REQUIRED');
   const c=envelope.claims;
   const payload=canonicalAdvisoryBytes(c);
   const key=this.#keys.get(c.domain_id);
   gate(!!key,'ORION_UNTRUSTED_DOMAIN');
   const t=this.#now();
   gate(Number.isSafeInteger(t) && t>=c.issued_at && t<c.expires_at &&
     c.issued_at<=t+30000,'ORION_CLAIM_EXPIRED');
   gate(typeof envelope.signature==='string' &&
     /^[A-Za-z0-9_-]{86}$/.test(envelope.signature),'ORION_SIGNATURE_DENIED');
   let verified=false;
   try {verified=verify(null,payload,key,Buffer.from(envelope.signature,'base64url'));}catch{}
   gate(verified,'ORION_SIGNATURE_DENIED');
   const nonceKey=c.domain_id+':'+c.nonce;
   gate(!this.#replays.has(nonceKey),'ORION_REPLAY_DENIED');
   const existing=this.#missions.get(c.mission_id)||[];
   gate(this.#accepted<this.#maxRecords,'ORION_CAPACITY_DENIED');
   gate(!existing.some(x=>x.domain_id===c.domain_id&&x.claim_id===c.claim_id),
     'ORION_DOMAIN_DUPLICATE_CLAIM');
   gate(!existing.some(x=>x.agent_id===c.agent_id && x.claim_id===c.claim_id),
     'ORION_AGENT_DUPLICATE_CLAIM');
   // A valid signature authenticates an input key only; not truth, authority or approval.
   this.#replays.add(nonceKey);this.#accepted++;
   existing.push({mission_id:c.mission_id,domain_id:c.domain_id,
    agent_id:c.agent_id,claim_id:c.claim_id,stance:c.stance,
    evidence_sha256:[...c.evidence_sha256],summary_sha256:sha256(c.summary),
    payload_sha256:sha256(payload)});
   this.#missions.set(c.mission_id,existing);
   this.#log('ACCEPTED_SIGNED_ADVISORY');
   return {status:'ACCEPTED_ADVISORY_ONLY',mission_id:c.mission_id,
    claim_id:c.claim_id,payload_sha256:sha256(payload),
    execution:'DENIED',approval:'NOT_GRANTED',audit_last_sha256:this.#last};
  } catch(err) {
   this.#log('REJECTED_ORION_SUBMISSION'); // Do not echo untrusted fields.
   throw err;
  }
 }
 report(missionId){
  boundId(missionId,MISSION);
  const records=this.#missions.get(missionId)||[];
  const groups=new Map();
  for(const rec of records){
   const arr=groups.get(rec.claim_id)||[];arr.push(clone(rec));
   groups.set(rec.claim_id,arr);
  }
  const claims=[...groups].sort(([a],[b])=>a.localeCompare(b)).map(([id,entries])=>{
   entries.sort((a,b)=>a.domain_id.localeCompare(b.domain_id));
   const distinctDomains=new Set(entries.map(x=>x.domain_id)).size;
   const opinions=new Set(entries.map(x=>x.stance));
   const conflict=opinions.has('FOR')&&opinions.has('AGAINST');
   const status=conflict?'CONTRADICTION_NEEDS_REVIEW':
     distinctDomains<2?'INSUFFICIENT_INDEPENDENT_DOMAINS':'UNCONTESTED_SIGNED_SUBMISSIONS';
   return {claim_id:id,status,independent_domain_count:distinctDomains,
    evidence_reference_count:entries.reduce((n,x)=>n+x.evidence_sha256.length,0),
    evidence_verified:false,domain_positions:entries.map(x=>({domain_id:x.domain_id,
     agent_id:x.agent_id,stance:x.stance,summary_sha256:x.summary_sha256,
     payload_sha256:x.payload_sha256,evidence_sha256:x.evidence_sha256})),
    review_question:conflict?'What externally verified evidence resolves these conflicting positions?':
     distinctDomains<2?'Can an authorized independent domain submit corroborating evidence?':
     'Have all referenced evidence artifacts been independently verified?'};
  });
  const payload={schema:'imperial_orion_advisory_report_v1',mission_id:missionId,
   report_status:claims.length?'ADVISORY_ONLY':'NO_SUBMISSIONS',claims,
   human_review_required:true,truth_verified:false,execution:'DENIED',
   task_dispatch:'DENIED',approval:'NOT_GRANTED',release:'DENIED',
   persistence:'IN_MEMORY_ONLY',global_orchestrator:false};
  return clone({...payload,report_sha256:sha256(JSON.stringify(payload)),
   audit_last_sha256:this.#last});
 }
 halt(){
  this.#halted=true;this.#log('OWNER_KILL_SWITCH');
  return {status:'HALTED',new_submissions:'DENIED',execution:'DENIED'};
 }
 snapshot(){return clone({schema:'imperial_orion_audit_v1',
  accepted_records:[...this.#missions.values()].reduce((a,b)=>a+b.length,0),
  trusted_domains:this.#keys.size,halted:this.#halted,events:this.#audit,
  audit_last_sha256:this.#last,persistence:'IN_MEMORY_ONLY',
  execution:'DENIED',production:'DENIED'});}
}
