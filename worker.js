// ============================================================
// Device Status — Cloudflare Worker  (v22)
// Manual alerts only — admin pushes via app UI.
// Notifications are stored per-user in KV so engineers can
// retrieve their full notification history from the app.
// ============================================================

const APP_URL = 'https://dswkochi.github.io/device-status/';

// VAPID keys — generate at: https://vapidkeys.com
const VAPID_PRIVATE_KEY = 'ml2CD3TlzmhWGKHBeI-53_L6FiZrj46-hpL1nWFink0';
const VAPID_PUBLIC_KEY  = 'BM057CxdrUyUjD7ymRq3DBrp1A2FkClluEmaz2YwOhYkpMaGypps3CFzJcx9sUjE-LG9TXtiuweFhLiaLmhueZQ';
const VAPID_SUBJECT     = 'mailto:admin@ldb.co.in';

// ── Web Push (VAPID) ─────────────────────────────────────────
function toBase64Url(buf){
  const bytes=buf instanceof Uint8Array?buf:new Uint8Array(buf);
  let str='';
  for(let i=0;i<bytes.length;i++)str+=String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function fromBase64Url(str){
  str=str.replace(/-/g,'+').replace(/_/g,'/');
  while(str.length%4)str+='=';
  const bin=atob(str);
  const buf=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
  return buf;
}
async function importVapidPrivateKey(b64urlKey){
  const raw=fromBase64Url(b64urlKey);
  const pkcs8Header=new Uint8Array([
    0x30,0x41,0x02,0x01,0x00,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
    0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x04,0x27,0x30,0x25,0x02,0x01,
    0x01,0x04,0x20
  ]);
  const pkcs8=new Uint8Array(pkcs8Header.length+raw.length);
  pkcs8.set(pkcs8Header);pkcs8.set(raw,pkcs8Header.length);
  return crypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
}
async function buildVapidJWT(endpoint){
  const url=new URL(endpoint);
  const audience=url.protocol+'//'+url.host;
  const expiry=Math.floor(Date.now()/1000)+12*3600;
  const hdr=toBase64Url(new TextEncoder().encode(JSON.stringify({typ:'JWT',alg:'ES256'})));
  const pld=toBase64Url(new TextEncoder().encode(JSON.stringify({aud:audience,exp:expiry,sub:VAPID_SUBJECT})));
  const input=new TextEncoder().encode(hdr+'.'+pld);
  const key=await importVapidPrivateKey(VAPID_PRIVATE_KEY);
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:{name:'SHA-256'}},key,input);
  const derSig=new Uint8Array(sig);
  let r,s;
  if(derSig[0]===0x30){
    let pos=2;pos++;
    const rLen=derSig[pos++];r=derSig.slice(pos,pos+rLen);pos+=rLen;
    pos++;const sLen=derSig[pos++];s=derSig.slice(pos,pos+sLen);
  }else{r=derSig.slice(0,32);s=derSig.slice(32,64);}
  const rPad=new Uint8Array(32);const sPad=new Uint8Array(32);
  rPad.set(r.length>32?r.slice(r.length-32):r,32-Math.min(r.length,32));
  sPad.set(s.length>32?s.slice(s.length-32):s,32-Math.min(s.length,32));
  const rawSig=new Uint8Array(64);rawSig.set(rPad);rawSig.set(sPad,32);
  return hdr+'.'+pld+'.'+toBase64Url(rawSig);
}
async function sendPush(subscription, payload){
  const endpoint = subscription.endpoint;
  const jwt = await buildVapidJWT(endpoint);
  const auth = 'vapid t=' + jwt + ', k=' + VAPID_PUBLIC_KEY;
  const bodyStr = JSON.stringify(payload);

  // Send as plain text — we are not doing end-to-end encryption of the payload.
  // The VAPID JWT authenticates the server; the payload travels over HTTPS.
  // Do NOT set Content-Encoding: aes128gcm unless the body is actually encrypted
  // (RFC 8291) — browsers silently drop messages with mismatched encoding.
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization': auth,
      'Content-Type': 'text/plain;charset=UTF-8',
      'TTL': '86400',
      'Urgency': 'high'
    },
    body: bodyStr
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    console.error('Push error:', res.status, txt);
  }
  return res;
}

// ── KV inbox helpers ─────────────────────────────────────────
// Key pattern: "inbox:<username>"  e.g. "inbox:ayush"
// Value: JSON array of { id, title, body, sentAt, sentBy }
async function appendToInbox(env,username,notification){
  const key='inbox:'+username;
  const existing=await env.PUSH_SUBS.get(key,{type:'json'})||[];
  existing.unshift(notification);          // newest first
  if(existing.length>200)existing.length=200;
  await env.PUSH_SUBS.put(key,JSON.stringify(existing));
}

// ── HTTP handler ─────────────────────────────────────────────
async function handleRequest(request,env){
  const url=new URL(request.url);
  const headers={'Access-Control-Allow-Origin':'*','Content-Type':'application/json'};

  if(request.method==='OPTIONS'){
    return new Response(null,{status:204,headers:{
      'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Max-Age':'86400'
    }});
  }

  // POST /subscribe
  if(url.pathname==='/subscribe'&&request.method==='POST'){
    const body=await request.json();
    const subs=await env.PUSH_SUBS.get('subscriptions',{type:'json'})||[];
    const filtered=subs.filter(s=>s.user!==body.user);
    filtered.push({user:body.user,engineer:body.engineer,subscription:body.subscription});
    await env.PUSH_SUBS.put('subscriptions',JSON.stringify(filtered));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // POST /unsubscribe
  if(url.pathname==='/unsubscribe'&&request.method==='POST'){
    const body=await request.json();
    const subs=await env.PUSH_SUBS.get('subscriptions',{type:'json'})||[];
    await env.PUSH_SUBS.put('subscriptions',JSON.stringify(subs.filter(s=>s.user!==body.user)));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // POST /manual-alert
  // Body: { title, body, recipients: ['ayush','swethaswan'], sender: 'admin' }
  // Always stores to KV inbox; also pushes if subscription exists.
  if(url.pathname==='/manual-alert'&&request.method==='POST'){
    const reqBody=await request.json();
    const {title,body:msgBody,recipients,sender}=reqBody;
    const alertTitle=title||'Alert from admin';
    const alertBody=msgBody||'';
    if(!recipients||!recipients.length){
      return new Response(JSON.stringify({ok:false,error:'No recipients'}),{status:400,headers});
    }
    const subs=await env.PUSH_SUBS.get('subscriptions',{type:'json'})||[];
    const userEngMap={'ayush':'Ayush E P','swethaswan':'Swethaswan'};
    let sent=0;
    const sentAt=new Date().toISOString();
    for(const username of recipients){
      const engName=userEngMap[username];
      // 1. Always store in KV inbox
      await appendToInbox(env,username,{
        id:Date.now()+'_'+username,
        title:alertTitle,body:alertBody,
        sentAt,sentBy:sender||'admin'
      });
      // 2. Push notification if subscribed
      const sub=subs.find(s=>s.user===username||s.engineer===engName);
      if(!sub){console.log('No push sub for',username,'— inbox only');continue;}
      try{
        await sendPush(sub.subscription,{title:alertTitle,body:alertBody,tag:'manual-alert-'+Date.now(),url:APP_URL});
        sent++;
      }catch(e){console.error('Push failed for',username,e.message);}
    }
    return new Response(JSON.stringify({ok:true,sent,total:recipients.length}),{headers});
  }

  // GET /inbox?user=<username>
  // Returns the stored notification history for a user.
  if(url.pathname==='/inbox'&&request.method==='GET'){
    const username=url.searchParams.get('user');
    if(!username){
      return new Response(JSON.stringify({ok:false,error:'Missing user param'}),{status:400,headers});
    }
    const inbox=await env.PUSH_SUBS.get('inbox:'+username,{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,inbox}),{headers});
  }

  // GET /get-credentials
  // Returns stored username + hash map. App fetches this on load so
  // credential changes made by admin propagate to every device.
  // KV key: "credentials"
  // Value: { ayush: {username, hash}, swethaswan: {username, hash} }
  if(url.pathname==='/get-credentials'&&request.method==='GET'){
    const creds=await env.PUSH_SUBS.get('credentials',{type:'json'})||{};
    return new Response(JSON.stringify({ok:true,credentials:creds}),{headers});
  }

  // POST /set-credentials
  // Body: { adminHash, credentials: { ayush:{username,hash}, swethaswan:{username,hash} } }
  // adminHash is sha256('admin:<password>') — verified against KV-stored or default hash.
  // Default admin hash (admin:admin123): c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951
  if(url.pathname==='/set-credentials'&&request.method==='POST'){
    const body=await request.json();
    const {adminHash,credentials}=body;
    if(!adminHash||!credentials){
      return new Response(JSON.stringify({ok:false,error:'Missing fields'}),{status:400,headers});
    }
    // Verify admin hash against stored or default
    const stored=await env.PUSH_SUBS.get('credentials',{type:'json'})||{};
    const expectedAdminHash=stored.admin?.hash||'c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951';
    if(adminHash!==expectedAdminHash){
      return new Response(JSON.stringify({ok:false,error:'Unauthorised'}),{status:401,headers});
    }
    // Validate: each entry needs username (3+ chars) and hash (64 hex chars)
    for(const [user,entry] of Object.entries(credentials)){
      if(!entry.username||entry.username.trim().length<3){
        return new Response(JSON.stringify({ok:false,error:'Username too short for '+user}),{status:400,headers});
      }
      if(!entry.hash||!/^[a-f0-9]{64}$/.test(entry.hash)){
        return new Response(JSON.stringify({ok:false,error:'Invalid hash for '+user}),{status:400,headers});
      }
    }
    // Merge: preserve admin entry, update engineer entries
    const updated={...stored};
    for(const [user,entry] of Object.entries(credentials)){
      updated[user]={username:entry.username.trim(),hash:entry.hash};
    }
    await env.PUSH_SUBS.put('credentials',JSON.stringify(updated));
    console.log('Credentials updated by admin. Users:',Object.keys(credentials).join(', '));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // POST /set-admin-password
  // Lets admin update their own password.
  // Body: { currentHash, newHash }
  if(url.pathname==='/set-admin-password'&&request.method==='POST'){
    const body=await request.json();
    const {currentHash,newHash}=body;
    if(!currentHash||!newHash){
      return new Response(JSON.stringify({ok:false,error:'Missing fields'}),{status:400,headers});
    }
    const stored=await env.PUSH_SUBS.get('credentials',{type:'json'})||{};
    const expectedHash=stored.admin?.hash||'c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951';
    if(currentHash!==expectedHash){
      return new Response(JSON.stringify({ok:false,error:'Current password incorrect'}),{status:401,headers});
    }
    if(!/^[a-f0-9]{64}$/.test(newHash)){
      return new Response(JSON.stringify({ok:false,error:'Invalid hash'}),{status:400,headers});
    }
    const updated={...stored,admin:{username:'admin',hash:newHash}};
    await env.PUSH_SUBS.put('credentials',JSON.stringify(updated));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /check-subs  (admin debug)
  if(url.pathname==='/check-subs'&&request.method==='GET'){
    const subs=await env.PUSH_SUBS.get('subscriptions',{type:'json'})||[];
    const summary=subs.map(s=>({user:s.user,engineer:s.engineer,
      endpoint:s.subscription?.endpoint?s.subscription.endpoint.substring(0,80)+'...':'none',
      hasKeys:!!(s.subscription?.keys)}));
    return new Response(JSON.stringify({ok:true,count:subs.length,subscribers:summary},null,2),{headers});
  }

  // GET /clear-subs  (admin debug)
  if(url.pathname==='/clear-subs'&&request.method==='GET'){
    await env.PUSH_SUBS.put('subscriptions',JSON.stringify([]));
    return new Response(JSON.stringify({ok:true,message:'All subscriptions cleared'}),{headers});
  }

  return new Response(JSON.stringify({error:'Not found',path:url.pathname}),{status:404,headers});
}

// ── Entry point ───────────────────────────────────────────────
export default {
  async fetch(request,env){
    return handleRequest(request,env);
  }
  // No scheduled handler — notifications are manual-only via admin UI.
};
