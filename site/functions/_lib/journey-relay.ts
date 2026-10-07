// Generated from site/marketing/relay.ts.
/** Shared same-origin relay. A property-specific key signs only browser observations. */
export interface JourneyEnv { SALESPOT_JOURNEY_HMAC_KEY?: string }
const TYPES = new Set(['page_view','cta_click','docs_open','install_click','form_start','form_success_view','demo_start','demo_complete','content_engaged']);
const JOURNEYS = new Set(['agent-code','platform-teams','technical-controls','private-deployment','developer-start','unassigned']);
const PRODUCTS = new Set(['platform','cilock','pushgate','appliance','unassigned']);
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const TOKEN = /^[a-zA-Z0-9][a-zA-Z0-9_.~-]{0,127}$/;
async function capped(response: Request | Response, limit: number): Promise<string> {
 const reader=response.body?.getReader();if(!reader)return '';
 const parts:Uint8Array[]=[];let length=0;
 try{for(;;){const {value,done}=await reader.read();if(done)break;length+=value.byteLength;if(length>limit){await reader.cancel();throw new Error('body too large')}parts.push(value)}}finally{reader.releaseLock()}
 const out=new Uint8Array(length);let offset=0;for(const part of parts){out.set(part,offset);offset+=part.length}return new TextDecoder().decode(out);
}
export async function journeyRelay(request:Request, env:JourneyEnv, property:string, send:typeof fetch=fetch):Promise<Response>{
 const reply=(status:number,data:Record<string,unknown>={})=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
 if(request.method!=='POST')return reply(405);
 const url=new URL(request.url);if(url.hostname.replace(/^www\./,'')!==property)return reply(403);
 if((request.headers.get('content-type')||'').split(';')[0].trim()!=='application/json')return reply(415);
 const origin=request.headers.get('origin'),site=request.headers.get('sec-fetch-site');
 if(origin&&origin!==url.origin||site&&site!=='same-origin'&&site!=='none')return reply(403);
 // Browser choice, not identity. A forged choice cannot grant product authority.
 if(!/(?:^|;\s*)ts_measurement=granted(?:;|$)/.test(request.headers.get('cookie')||'')||request.headers.get('sec-gpc')==='1')return reply(403);
 if(!env.SALESPOT_JOURNEY_HMAC_KEY)return reply(503);
 let input:Record<string,unknown>;try{input=JSON.parse(await capped(request,8192));if(!input||Array.isArray(input))return reply(400)}catch{return reply(400)}
 if(input.schema!=='testifysec.webjourney.v1'||typeof input.event_id!=='string'||!UUID.test(input.event_id)||typeof input.journey_id!=='string'||!UUID.test(input.journey_id)||!TYPES.has(String(input.type))||!JOURNEYS.has(String(input.journey))||!PRODUCTS.has(String(input.product))||typeof input.path!=='string'||!/^\/[a-zA-Z0-9/_-]{0,250}$/.test(input.path)||input.consent_version!==1)return reply(400);
 const occurred=typeof input.occurred_at==='string'?Date.parse(input.occurred_at):NaN;
 if(!Number.isFinite(occurred)||occurred>Date.now()+300000||occurred<Date.now()-86400000)return reply(400);
 const wire:Record<string,unknown>={schema:input.schema,event_id:input.event_id,journey_id:input.journey_id,property,type:input.type,journey:input.journey,product:input.product,path:input.path,occurred_at:input.occurred_at,consent_version:1};
 for(const key of ['first_campaign','last_campaign','utm_source','utm_medium','utm_content']){const value=input[key];if(value!==''&&value!==undefined&&(typeof value!=='string'||!TOKEN.test(value)))return reply(400);wire[key]=value||'';}
 const body=JSON.stringify(wire),ts=Math.floor(Date.now()/1000),encoder=new TextEncoder();
 const key=await crypto.subtle.importKey('raw',encoder.encode(env.SALESPOT_JOURNEY_HMAC_KEY),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const signature=[...new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(`${ts}.${body}`)))].map(x=>x.toString(16).padStart(2,'0')).join('');
 const headers:Record<string,string>={'Content-Type':'application/json','X-Ingest-Signature':`t=${ts},v1=${signature}`};
 const ip=request.headers.get('cf-connecting-ip');if(ip)headers['CF-Connecting-IP']=ip;
 try{
  const upstream=await send('https://salespot.testifysec.com/ingest/web/journey',{method:'POST',headers,body,redirect:'manual',signal:AbortSignal.timeout(4000)});
  if(upstream.status!==202){await upstream.body?.cancel();return reply(502)}
  const receipt=JSON.parse(await capped(upstream,2048));
  if(receipt.accepted!==true||receipt.event_id!==input.event_id||receipt.evidence!=='browser_observation')return reply(502);
  return reply(202,{accepted:true,event_id:input.event_id,replay:receipt.replay===true});
 }catch{return reply(502)}
}
