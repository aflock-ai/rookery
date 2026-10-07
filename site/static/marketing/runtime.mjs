import {campaignFromURL,updateAttribution,routeContext,handoffURL,readHandoff,eventFor,PROPERTY_HOSTS} from './model.mjs';
// A single lightweight implementation shared by all three public properties.
// Local previews never contact production analytics.
const property=location.hostname.replace(/^www\./,'');
if (PROPERTY_HOSTS.includes(location.hostname) && !window.testifyJourney) boot();
function boot(){
 const cookie=name=>document.cookie.split('; ').find(c=>c.startsWith(name+'='))?.slice(name.length+1)||'';
 const setCookie=(name,value,age)=>{document.cookie=`${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${age}; SameSite=Lax; Secure`;};
 const privacy=()=>navigator.globalPrivacyControl===true||navigator.doNotTrack==='1';
 const storage={get(key){try{return JSON.parse(localStorage.getItem(key)||'null')}catch{return null}},set(key,value){try{localStorage.setItem(key,JSON.stringify(value))}catch{}},remove(key){try{localStorage.removeItem(key)}catch{}}};
 let consented=cookie('ts_measurement')==='granted'&&!privacy();
 let state={property,consented,journey_id:'',attribution:null};
 let lastPath='',sent=new Set(),context=routeContext(property,location.pathname),pendingURL=location.href;
 const types=new Set(['page_view','cta_click','docs_open','install_click','form_start','form_success_view','demo_start','demo_complete','content_engaged']);
 function initialize(){
  const handoff=readHandoff(pendingURL,true);
  const previous=storage.get('ts_journey');
  const active=previous?.expires_at>Date.now();
  state={...state,consented:true,journey_id:handoff?.journey_id||(active?previous.journey_id:crypto.randomUUID()),attribution:updateAttribution(handoff?.attribution||(active?previous.attribution:null),campaignFromURL(pendingURL))};
  storage.set('ts_journey',{...state,expires_at:Date.now()+90*86400000});
  // This is an anonymous observation ID; never a platform session credential.
  setCookie('ts_jid',state.journey_id,90*86400);
  page();
 }
 function cleanHandoff(){if(new URL(location.href).searchParams.has('_tsj')){const url=new URL(location.href);url.searchParams.delete('_tsj');history.replaceState(history.state,'',url.pathname+url.search+url.hash)}}
 function send(type){
  if(!state.consented||privacy()||!types.has(type))return;
  const key=context.path+':'+type;if(sent.has(key)&&type!=='cta_click')return;sent.add(key);
  const event=eventFor(state,type,context,crypto.randomUUID());
  // A finite event schema, with no DOM text, form values, clipboard content,
  // search terms, full referrer URLs, client fingerprint or ad click identifier.
  fetch('/api/journey',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(event),keepalive:true,redirect:'error'}).then(async response=>{
   let accepted=false;try{accepted=response.status===202&&(await response.json()).accepted===true}catch{}
   window.dispatchEvent(new CustomEvent('testify:journey-receipt',{detail:{event_id:event.event_id,accepted,status:response.status}}));
  }).catch(()=>window.dispatchEvent(new CustomEvent('testify:journey-receipt',{detail:{event_id:event.event_id,accepted:false,status:0}})));
 }
 function page(){
  const path=location.pathname;if(path===lastPath)return;lastPath=path;context=routeContext(property,path);sent=new Set();send('page_view');
 }
 function choice(granted){
  consented=granted&&!privacy();setCookie('ts_measurement',consented?'granted':'denied',180*86400);setCookie('cl_consent',consented?'granted':'denied',180*86400);
  state.consented=consented;document.getElementById('ts-consent')?.remove();
  if(consented){initialize()}else{storage.remove('ts_journey');setCookie('ts_jid','',0);state={property,consented:false,journey_id:'',attribution:null};}
  // Optional advertising destinations stay controlled by the same user choice.
  try{window.zaraz?.consent?.setAll(consented)}catch{}
 }
 function banner(){
  if(document.getElementById('ts-consent'))return;
  const bar=document.createElement('aside');bar.id='ts-consent';bar.setAttribute('aria-label','Measurement preferences');
  bar.innerHTML='<p>May we measure how you use our sites? This helps us improve the products and documentation. <a href="https://testifysec.com/privacy-policy">Privacy</a></p><div><button type="button" data-choice="no">Necessary only</button><button type="button" data-choice="yes">Allow measurement</button></div>';
  const style=document.createElement('style');style.textContent='#ts-consent{position:fixed;z-index:10000;left:16px;right:16px;bottom:16px;max-width:1050px;margin:auto;padding:18px 20px;background:#fff;color:#172033;border:1px solid #d9dfe7;border-radius:12px;box-shadow:0 8px 40px #0f172a26;display:flex;align-items:center;gap:20px;font:14px/1.5 system-ui,sans-serif}#ts-consent p{margin:0;flex:1}#ts-consent a{color:#000066;text-decoration:underline}#ts-consent>div{display:flex;gap:8px;flex-wrap:wrap}#ts-consent button{font:600 13px system-ui;border:1px solid #bac5d4;border-radius:6px;padding:12px;min-height:44px;background:white;color:#172033;cursor:pointer}#ts-consent button[data-choice=yes]{background:#ffa624;border-color:#ffa624}#ts-consent button:focus-visible{outline:3px solid #000066;outline-offset:2px}@media(max-width:650px){#ts-consent{flex-direction:column;align-items:stretch;gap:12px;left:8px;right:8px;bottom:8px}}';
  bar.prepend(style);bar.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>choice(button.dataset.choice==='yes')));document.body.append(bar);
 }
 window.testifyJourney={track:send,page,preferences:banner,attribution:()=>state.consented?state.attribution?.last||{}:{}};
 document.addEventListener('click',event=>{
  const element=event.target instanceof Element?event.target:null;
  const link=element?.closest('a[href]');const marked=element?.closest('[data-journey-event]');
  if(marked)send(marked.getAttribute('data-journey-event'));
  if(link){
   const url=new URL(link.href,location.href);
   if(!marked){if(url.pathname.includes('/docs'))send('docs_open');else if(/\/(install|download|dl)(\/|$)/.test(url.pathname))send('install_click');else if(link.className.includes('button')||link.closest('nav')||url.hostname!==location.hostname)send('cta_click');}
   if(state.consented&&url.hostname!==location.hostname){link.href=handoffURL(link.href,location.href,state);}
  }
 });
 document.addEventListener('focusin',event=>{if(event.target instanceof Element&&event.target.closest('form[id^="lead-form-"]'))send('form_start')});
 for(const method of ['pushState','replaceState']){const original=history[method];history[method]=function(...args){const result=original.apply(this,args);queueMicrotask(page);return result;}}
 window.addEventListener('popstate',page);
 document.addEventListener('testify:measurement-settings',banner);
 cleanHandoff();
 if(consented)initialize();else if(!cookie('ts_measurement')&&!privacy())banner();
 // Remove obsolete local campaign stores so the form cannot pick up stale
 // attribution from the retired tracker. Does not touch CRM or customer data.
 try{sessionStorage.removeItem('current_attribution')}catch{}
 for(const name of ['testify_attr','testify_uid','testify_vtype','testify_fv','testify_company'])setCookie(name,'',0);
}
