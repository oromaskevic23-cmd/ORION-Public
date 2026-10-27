import {createHash} from 'node:crypto';

const ID=/^[A-Za-z][A-Za-z0-9_-]{2,63}$/;
const ACTIONS=new Set(['RECOMMEND','REVIEW','ESCALATE']);
const canonical=value=>JSON.stringify(value);
const digest=value=>createHash('sha256').update(canonical(value)).digest('hex');
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.getPrototypeOf(o)===Object.prototype;
function keys(o,expected){
 if(!plain(o)||Object.keys(o).sort().join('|')!==expected.slice().sort().join('|'))throw Error('INVALID_CONTRACT');
}
export function deliberate({taskId,question,participants,minimumQuorum=2}={}){
 if(!ID.test(taskId||'')||typeof question!=='string'||question.trim().length<12||question.length>2000||
  !Array.isArray(participants)||participants.length<2||participants.length>32||
  !Number.isInteger(minimumQuorum)||minimumQuorum<2||minimumQuorum>participants.length)
  throw Error('INVALID_COUNCIL_REQUEST');
 const seen=new Set(),votes=[];
 for(const p of participants){
  keys(p,['agentId','passport','capabilities','vote','reason']);
  if(!ID.test(p.agentId||'')||seen.has(p.agentId)||!plain(p.passport)||
   p.passport.agentId!==p.agentId||p.passport.status!=='ACTIVE'||
   !Array.isArray(p.capabilities)||!p.capabilities.includes('ORION_DELIBERATE')||
   !ACTIONS.has(p.vote)||typeof p.reason!=='string'||p.reason.trim().length<8||p.reason.length>1000)
   throw Error('AGENT_IDENTITY_OR_CAPABILITY_DENIED');
  seen.add(p.agentId);
  votes.push({agentId:p.agentId,vote:p.vote,reason:p.reason});
 }
 const counts=Object.fromEntries([...ACTIONS].map(v=>[v,votes.filter(x=>x.vote===v).length]));
 const ordered=Object.entries(counts).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));
 const winner=ordered[0],tie=ordered[1][1]===winner[1];
 const outcome=!tie&&winner[1]>=minimumQuorum?winner[0]:'NO_CONSENSUS';
 const evidence={schema:'orion_enterprise_deliberation_v1',taskId,question,votes,counts,
  quorum:minimumQuorum,outcome,executionAuthorized:false,approval:'OWNER_REQUIRED',
  boundary:'RECOMMENDATION_ONLY'};
 return Object.freeze({...evidence,evidenceSha256:digest(evidence)});
}
