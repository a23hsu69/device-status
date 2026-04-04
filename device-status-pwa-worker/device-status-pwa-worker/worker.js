// ============================================================
// Field Manager — Cloudflare Worker  (v6.0)
// Manual alerts only — admin pushes via app UI.
// Notifications are stored per-user in KV so engineers can
// retrieve their full notification history from the app.
// Device list stored in KV — synced to all clients on login.
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
// ── Web Push encryption (RFC 8291 / draft-ietf-webpush-encryption) ───────────
// Cloudflare Workers support crypto.subtle so we can do real ECDH + AES-GCM.
// This is required for FCM (Android Chrome) to deliver the payload body.

async function sendPush(subscription, payload) {
  const endpoint = subscription.endpoint;
  const keys     = subscription.keys; // { p256dh, auth }

  const jwt  = await buildVapidJWT(endpoint);
  const auth = 'vapid t=' + jwt + ', k=' + VAPID_PUBLIC_KEY;

  // If no keys provided, send a keyless ping (payload will be null in SW)
  if (!keys || !keys.p256dh || !keys.auth) {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Authorization': auth, 'TTL': '86400', 'Urgency': 'high' }
    });
    if (!res.ok) { const t = await res.text().catch(()=>''); console.error('Push (no-key) error:', res.status, t); }
    return res;
  }

  // Encrypt payload per RFC 8291
  const encryptedBody = await encryptPayload(JSON.stringify(payload), keys.p256dh, keys.auth);

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization':    auth,
      'Content-Type':     'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL':              '86400',
      'Urgency':          'high'
    },
    body: encryptedBody
  });
  if (!res.ok) { const t = await res.text().catch(()=>''); console.error('Push error:', res.status, t); }
  return res;
}

// RFC 8291 payload encryption using ECDH + HKDF + AES-128-GCM
async function encryptPayload(plaintext, p256dhB64, authB64) {
  const subtle = crypto.subtle;

  // Decode subscriber's public key and auth secret
  const subscriberPublicKeyBytes = fromBase64Url(p256dhB64);
  const authSecret               = fromBase64Url(authB64);

  // Import subscriber's public key
  const subscriberPublicKey = await subtle.importKey(
    'raw', subscriberPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );

  // Generate ephemeral ECDH key pair
  const ephemeralKeyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveKey', 'deriveBits']
  );

  // Export ephemeral public key (uncompressed, 65 bytes)
  const ephemeralPublicKeyBytes = new Uint8Array(
    await subtle.exportKey('raw', ephemeralKeyPair.publicKey)
  );

  // ECDH shared secret
  const sharedSecretBits = await subtle.deriveBits(
    { name: 'ECDH', public: subscriberPublicKey },
    ephemeralKeyPair.privateKey, 256
  );
  const sharedSecret = new Uint8Array(sharedSecretBits);

  // Generate salt (16 random bytes)
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // HKDF-Extract: PRK = HMAC-SHA256(auth, sharedSecret + subscriberPublicKey + ephemeralPublicKey)
  const enc = new TextEncoder();

  // IKM = HKDF-Extract with auth secret
  const ikmKey = await subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveBits']);
  const prkInfo = concat(enc.encode('WebPush: info\x00'), subscriberPublicKeyBytes, ephemeralPublicKeyBytes);
  const prk = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: authSecret, info: prkInfo },
    ikmKey, 256
  );

  // CEK + nonce derivation
  const prkKey = await subtle.importKey('raw', prk, { name: 'HKDF' }, false, ['deriveBits']);

  const cekInfo   = enc.encode('Content-Encoding: aes128gcm\x00');
  const nonceInfo = enc.encode('Content-Encoding: nonce\x00');

  const cekBits   = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: cekInfo   }, prkKey, 128);
  const nonceBits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: nonceInfo }, prkKey, 96);

  const cek   = await subtle.importKey('raw', cekBits, { name: 'AES-GCM' }, false, ['encrypt']);
  const nonce = new Uint8Array(nonceBits);

  // Pad plaintext: append 0x02 delimiter then zeros up to 3992 bytes max
  const plaintextBytes = enc.encode(plaintext);
  const paddedLen      = Math.min(plaintextBytes.length + 1, 3992);
  const padded         = new Uint8Array(paddedLen);
  padded.set(plaintextBytes);
  padded[plaintextBytes.length] = 0x02; // padding delimiter

  // Encrypt
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, cek, padded)
  );

  // Build RFC 8291 header: salt(16) + rs(4) + keyid_len(1) + ephemeral_public_key(65)
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false); // record size
  const header = concat(salt, rs, new Uint8Array([65]), ephemeralPublicKeyBytes);

  return concat(header, ciphertext);
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out   = new Uint8Array(total);
  let   off   = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
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

  // POST /clear-inbox
  // Clears a user's notification inbox from KV.
  // Body: { user: 'ayush' | 'swethaswan' }
  if(url.pathname==='/clear-inbox'&&request.method==='POST'){
    const body=await request.json();
    const {user}=body;
    if(!user){
      return new Response(JSON.stringify({ok:false,error:'Missing user'}),{status:400,headers});
    }
    await env.PUSH_SUBS.put('inbox:'+user,JSON.stringify([]));
    return new Response(JSON.stringify({ok:true}),{headers});
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
  // Body: { adminHash, credentials: { ayush:{username,hash}, swethaswan:{username,hash} }, removedKeys:[] }
  // adminHash is sha256('admin:<password>') — verified against KV-stored or default hash.
  // Default admin hash (admin:admin123): c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951
  if(url.pathname==='/set-credentials'&&request.method==='POST'){
    const body=await request.json();
    const {adminHash,credentials,removedKeys=[]}=body;
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
    // Merge: preserve admin entry, update engineer entries (preserve role and name)
    const updated={...stored};
    for(const [user,entry] of Object.entries(credentials)){
      updated[user]={
        username:entry.username.trim(),
        hash:entry.hash,
        role:entry.role||'engineer',
        name:entry.name||entry.username.trim()
      };
    }
    // Delete removed users — never allow removing the core admin account
    for(const key of removedKeys){
      if(key!=='admin') delete updated[key];
    }
    await env.PUSH_SUBS.put('credentials',JSON.stringify(updated));
    console.log('Credentials updated by admin. Users:',Object.keys(updated).filter(k=>k!=='admin').join(', '),removedKeys.length?'| Removed: '+removedKeys.join(', '):'');
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

  // POST /submit-report
  // Called when an engineer sends a report. Stores it in KV so admin can see it.
  // Body: { user, subject, reportBody (or body), type, ts }
  // KV key: "reports" — array of report objects, newest first, max 200
  if(url.pathname==='/submit-report'&&request.method==='POST'){
    const body=await request.json();
    const {user,subject,type,ts}=body;
    const reportBody=body.reportBody||body.body||'';
    if(!user||!subject){
      return new Response(JSON.stringify({ok:false,error:'Missing fields'}),{status:400,headers});
    }
    const reports=await env.PUSH_SUBS.get('reports',{type:'json'})||[];
    reports.unshift({
      id:ts+'_'+user,
      user,subject,
      body:reportBody||'',
      type:type||'report',
      ts:ts||Date.now()
    });
    if(reports.length>200)reports.length=200;
    await env.PUSH_SUBS.put('reports',JSON.stringify(reports));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /get-reports
  // Admin fetches all submitted reports.
  if(url.pathname==='/get-reports'&&request.method==='GET'){
    const reports=await env.PUSH_SUBS.get('reports',{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,reports}),{headers});
  }

  // GET /get-contacts
  // Returns admin-configured mail contact list.
  if(url.pathname==='/get-contacts'&&request.method==='GET'){
    const contacts=await env.PUSH_SUBS.get('mail_contacts',{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,contacts}),{headers});
  }

  // POST /set-contacts
  // Admin saves the mail contact list.
  // Body: { contacts: [ { id, name, email, role } ] }
  if(url.pathname==='/set-contacts'&&request.method==='POST'){
    const body=await request.json();
    const {contacts}=body;
    if(!Array.isArray(contacts)){
      return new Response(JSON.stringify({ok:false,error:'contacts must be an array'}),{status:400,headers});
    }
    await env.PUSH_SUBS.put('mail_contacts',JSON.stringify(contacts));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // POST /submit-leave
  // Engineer submits a leave request — stored in KV for admin to see.
  // Body: { id, user, name, subject, body, fromDate, toDate, days, reason, ts, status }
  if(url.pathname==='/submit-leave'&&request.method==='POST'){
    const body=await request.json();
    if(!body.user||!body.subject){
      return new Response(JSON.stringify({ok:false,error:'Missing fields'}),{status:400,headers});
    }
    const leaves=await env.PUSH_SUBS.get('leave_requests',{type:'json'})||[];
    // Avoid duplicates by id
    const filtered=leaves.filter(l=>l.id!==body.id);
    filtered.unshift({...body,status:body.status||'pending'});
    if(filtered.length>500)filtered.length=500;
    await env.PUSH_SUBS.put('leave_requests',JSON.stringify(filtered));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /get-leaves
  // Admin fetches all leave requests.
  if(url.pathname==='/get-leaves'&&request.method==='GET'){
    const leaves=await env.PUSH_SUBS.get('leave_requests',{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,leaves}),{headers});
  }

  // POST /update-leave
  // Admin approves or declines a leave request.
  // Body: { id, status: 'approved' | 'declined' }
  if(url.pathname==='/update-leave'&&request.method==='POST'){
    const body=await request.json();
    const {id,status}=body;
    if(!id||!status){
      return new Response(JSON.stringify({ok:false,error:'Missing id or status'}),{status:400,headers});
    }
    const leaves=await env.PUSH_SUBS.get('leave_requests',{type:'json'})||[];
    const updated=leaves.map(l=>l.id===id?{...l,status}:l);
    await env.PUSH_SUBS.put('leave_requests',JSON.stringify(updated));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /get-sites — returns admin-managed distant sites list
  if(url.pathname==='/get-sites'&&request.method==='GET'){
    const sites=await env.PUSH_SUBS.get('distant_sites',{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,sites}),{headers});
  }

  // POST /set-sites — admin saves the distant sites list
  if(url.pathname==='/set-sites'&&request.method==='POST'){
    const body=await request.json();
    if(!Array.isArray(body.sites)){
      return new Response(JSON.stringify({ok:false,error:'sites must be array'}),{status:400,headers});
    }
    await env.PUSH_SUBS.put('distant_sites',JSON.stringify(body.sites));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // POST /submit-visit — engineer submits a visit request
  if(url.pathname==='/submit-visit'&&request.method==='POST'){
    const body=await request.json();
    if(!body.user||!body.subject){
      return new Response(JSON.stringify({ok:false,error:'Missing fields'}),{status:400,headers});
    }
    const visits=await env.PUSH_SUBS.get('visit_requests',{type:'json'})||[];
    visits.unshift({...body,id:Date.now()+'_'+body.user});
    if(visits.length>300)visits.length=300;
    await env.PUSH_SUBS.put('visit_requests',JSON.stringify(visits));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /get-visits — admin fetches all visit requests
  if(url.pathname==='/get-visits'&&request.method==='GET'){
    const visits=await env.PUSH_SUBS.get('visit_requests',{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,visits}),{headers});
  }

  // GET /fetch-devices — CORS proxy for LDB device status API
  if(url.pathname==='/fetch-devices'&&request.method==='GET'){
    const LDB_HTTPS = 'https://devicehealth.ldb.co.in:8181/api/DeviceStatus/DownloadAndProcess';
    const LDB_HTTP  = 'http://devicehealth.ldb.co.in:8181/api/DeviceStatus/DownloadAndProcess';
    const fetchOpts = {
      headers:{'User-Agent':'Mozilla/5.0','Accept':'text/csv,text/plain,*/*'},
      signal: AbortSignal.timeout(20000)
    };
    // Try HTTPS first, fall back to HTTP if TLS fails
    for(const ldbUrl of [LDB_HTTPS, LDB_HTTP]){
      try{
        const r=await fetch(ldbUrl,fetchOpts);
        const text=await r.text();
        if(!r.ok){
          return new Response(JSON.stringify({ok:false,error:'Upstream HTTP '+r.status,url:ldbUrl,detail:text.slice(0,300)}),{status:502,headers});
        }
        return new Response(text,{headers:{...headers,'Content-Type':'text/plain','Cache-Control':'no-store'}});
      }catch(e){
        // If this was the HTTP attempt too, return the error
        if(ldbUrl===LDB_HTTP){
          return new Response(JSON.stringify({ok:false,error:e.message,type:e.constructor.name,tried:'both https and http'}),{status:502,headers});
        }
        // Otherwise try HTTP next
        continue;
      }
    }
  }

  // POST /gmail-draft — proxy to Google Apps Script to avoid CORS
  // Body: { scriptUrl, to, cc, subject, html, plain }
  if(url.pathname==='/gmail-draft'&&request.method==='POST'){
    try{
      const body=await request.json();
      const {scriptUrl,...payload}=body;
      if(!scriptUrl){
        return new Response(JSON.stringify({ok:false,error:'No scriptUrl provided'}),{status:400,headers});
      }
      const r=await fetch(scriptUrl,{
        method:'POST',
        redirect:'follow',
        headers:{'Content-Type':'application/json','Accept':'application/json'},
        body:JSON.stringify(payload)
      });
      const text=await r.text();
      // Detect if Google returned a login/error HTML page
      if(text.trim().startsWith('<!DOCTYPE')||text.trim().startsWith('<html')){
        return new Response(JSON.stringify({
          ok:false,
          error:'Apps Script returned HTML — check deployment settings: Execute as Me, Anyone can access'
        }),{status:502,headers});
      }
      let result;
      try{ result=JSON.parse(text); }catch(e){ result={ok:false,error:text.slice(0,200)}; }
      return new Response(JSON.stringify(result),{headers});
    }catch(e){
      return new Response(JSON.stringify({ok:false,error:e.message}),{status:502,headers});
    }
  }

  // GET /get-visit-contacts?type=approval|advance
  if(url.pathname==='/get-visit-contacts'&&request.method==='GET'){
    const type=url.searchParams.get('type')||'approval';
    const key='visit_contacts_'+type;
    const contacts=await env.PUSH_SUBS.get(key,{type:'json'})||[];
    return new Response(JSON.stringify({ok:true,contacts}),{headers});
  }

  // POST /set-visit-contacts — admin saves visit contact list
  // Body: { type: 'approval'|'advance', contacts: [...] }
  if(url.pathname==='/set-visit-contacts'&&request.method==='POST'){
    const body=await request.json();
    const {type,contacts}=body;
    if(!type||!Array.isArray(contacts)){
      return new Response(JSON.stringify({ok:false,error:'Missing type or contacts'}),{status:400,headers});
    }
    const key='visit_contacts_'+type;
    await env.PUSH_SUBS.put(key,JSON.stringify(contacts));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /device-list — returns full device list with version for sync check
  if(url.pathname==='/device-list'&&request.method==='GET'){
    const stored=await env.PUSH_SUBS.get('device_list',{type:'json'})||{version:0,updatedAt:null,source:'none',fetchUrl:'',devices:[]};
    return new Response(JSON.stringify({ok:true,...stored}),{headers});
  }

  // POST /device-list — admin saves device list
  // Body: { devices:[{site,mac,assetId,label}], source, fetchUrl, version }
  if(url.pathname==='/device-list'&&request.method==='POST'){
    const body=await request.json();
    if(!Array.isArray(body.devices)){
      return new Response(JSON.stringify({ok:false,error:'devices must be an array'}),{status:400,headers});
    }
    const payload={
      version:   body.version||Date.now(),
      updatedAt: new Date().toISOString(),
      source:    body.source||'manual',
      fetchUrl:  body.fetchUrl||'',
      devices:   body.devices
    };
    await env.PUSH_SUBS.put('device_list',JSON.stringify(payload));
    return new Response(JSON.stringify({ok:true,count:body.devices.length}),{headers});
  }

  // POST /set-fetch-url — admin saves the CSV fetch URL
  // Body: { url }
  if(url.pathname==='/set-fetch-url'&&request.method==='POST'){
    const body=await request.json();
    if(!body.url){return new Response(JSON.stringify({ok:false,error:'Missing url'}),{status:400,headers});}
    const stored=await env.PUSH_SUBS.get('device_list',{type:'json'})||{version:0,devices:[]};
    stored.fetchUrl=body.url.trim();
    await env.PUSH_SUBS.put('device_list',JSON.stringify(stored));
    return new Response(JSON.stringify({ok:true}),{headers});
  }

  // GET /fetch-from-url — one-time trigger: fetch CSV from stored URL, parse, save to KV
  if(url.pathname==='/fetch-from-url'&&request.method==='GET'){
    const stored=await env.PUSH_SUBS.get('device_list',{type:'json'})||{};
    const fetchUrl=stored.fetchUrl||'';
    if(!fetchUrl){return new Response(JSON.stringify({ok:false,error:'No fetch URL configured'}),{status:400,headers});}
    const tryUrls=[fetchUrl];
    if(fetchUrl.startsWith('https://'))tryUrls.push(fetchUrl.replace('https://','http://'));
    let csvText=null;
    for(const u of tryUrls){
      try{
        const r=await fetch(u,{headers:{'User-Agent':'Mozilla/5.0','Accept':'text/csv,text/plain,*/*'},signal:AbortSignal.timeout(20000)});
        if(r.ok){csvText=await r.text();break;}
      }catch(e){continue;}
    }
    if(!csvText){return new Response(JSON.stringify({ok:false,error:'Could not fetch from URL'}),{status:502,headers});}
    const lines=csvText.split(/\r?\n/).filter(l=>l.trim());
    if(lines.length<2){return new Response(JSON.stringify({ok:false,error:'CSV has no data rows'}),{status:422,headers});}
    const hdr=lines[0].split(',').map(h=>h.replace(/^"|"$/g,'').trim().toLowerCase());
    const iSite =hdr.findIndex(h=>h.includes('location')||h.includes('site'));
    const iMac  =hdr.findIndex(h=>h.includes('mac')||h.includes('asset_id')||h.includes('device'));
    const iLabel=hdr.findIndex(h=>h.includes('label')||h.includes('position')||(h.includes('asset')&&!h.includes('id')));
    const devices=[];
    for(let i=1;i<lines.length;i++){
      const cols=lines[i].split(',').map(c=>c.replace(/^"|"$/g,'').trim());
      const site =(iSite >=0?cols[iSite] :cols[4]||'').trim();
      const mac  =(iMac  >=0?cols[iMac]  :cols[0]||'').trim().toUpperCase();
      const label=(iLabel>=0?cols[iLabel]:'').trim();
      if(!site||!mac)continue;
      devices.push({site,mac,assetId:label,label});
    }
    const payload={version:Date.now(),updatedAt:new Date().toISOString(),source:'url_fetch',fetchUrl,devices};
    await env.PUSH_SUBS.put('device_list',JSON.stringify(payload));
    return new Response(JSON.stringify({ok:true,count:devices.length,...payload}),{headers});
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
