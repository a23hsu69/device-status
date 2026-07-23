// ============================================================
// Field Manager — Cloudflare Worker  (v7.0 — Phase 2)
// Phase 1: Reporter role, dynamic userEngMap, leave quota,
//          ack sync to KV, approvedBy on leave/visit
// Phase 2: Reporter summary endpoint, CSV downloads,
//          alert ack tracking per recipient
// Dev: Ayush E P | RFID Engineer — Cochin Port
// ============================================================

const APP_URL = 'https://dswkochi.github.io/device-status/';

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
  const jwt  = await buildVapidJWT(endpoint);
  const auth = 'vapid t=' + jwt + ', k=' + VAPID_PUBLIC_KEY;
  const res  = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Authorization':auth, 'Content-Type':'text/plain;charset=UTF-8', 'TTL':'86400', 'Urgency':'high' },
    body: JSON.stringify(payload)
  });
  if(!res.ok){ const t=await res.text().catch(()=>''); console.error('Push error:',res.status,t); }
  return res;
}

// ── KV inbox helpers ─────────────────────────────────────────
async function appendToInbox(env, username, notification){
  const key      = 'inbox:' + username;
  const existing = await env.PUSH_SUBS.get(key, {type:'json'}) || [];
  existing.unshift(notification);
  if(existing.length > 200) existing.length = 200;
  await env.PUSH_SUBS.put(key, JSON.stringify(existing));
}

// ── Dynamic userEngMap from KV ────────────────────────────────
async function buildUserEngMap(env){
  const creds = await env.PUSH_SUBS.get('credentials', {type:'json'}) || {};
  const map   = { ayush:'Ayush E P', swethaswan:'Swethaswan' };
  for(const [key, entry] of Object.entries(creds)){
    if(!entry || !entry.username || key.startsWith('__removed_')) continue;
    if(entry.role === 'engineer' || entry.role === 'admin'){
      map[key] = entry.name || entry.username;
    }
  }
  return map;
}

// ── Role validation ───────────────────────────────────────────
function isValidRole(role){ return ['admin','engineer','reporter'].includes(role); }

// ── PHASE 2: Date helpers ─────────────────────────────────────
function getMonthBounds(yearMonth){
  // yearMonth = 'YYYY-MM'
  const [y, m] = yearMonth.split('-').map(Number);
  const start  = new Date(y, m - 1, 1, 0, 0, 0, 0);
  const end    = new Date(y, m,     1, 0, 0, 0, 0); // exclusive
  return { start, end };
}

function inMonth(tsOrStr, yearMonth){
  const ts  = typeof tsOrStr === 'number' ? tsOrStr : new Date(tsOrStr).getTime();
  if(!ts || isNaN(ts)) return false;
  const { start, end } = getMonthBounds(yearMonth);
  return ts >= start.getTime() && ts < end.getTime();
}

function fmtDate(tsOrStr){
  if(!tsOrStr) return '';
  const d = typeof tsOrStr === 'number' ? new Date(tsOrStr) : new Date(tsOrStr);
  return d.toLocaleDateString('en-IN', { day:'2-digit', month:'2-digit', year:'numeric' });
}

function fmtDateTime(tsOrStr){
  if(!tsOrStr) return '';
  const d = typeof tsOrStr === 'number' ? new Date(tsOrStr) : new Date(tsOrStr);
  return d.toLocaleString('en-IN', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

// ── PHASE 2: CSV builder ──────────────────────────────────────
// Properly escapes values per RFC 4180
function csvEscape(val){
  const s = String(val == null ? '' : val);
  if(s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')){
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function buildCsv(headers, rows){
  const lines = [headers.map(csvEscape).join(',')];
  for(const row of rows){
    lines.push(row.map(csvEscape).join(','));
  }
  return lines.join('\r\n');
}

// ── PHASE 2: Get engineer list from KV ───────────────────────
async function getEngineerList(env){
  const creds = await env.PUSH_SUBS.get('credentials', {type:'json'}) || {};
  const list  = [];
  // Always include core engineers
  const core  = { ayush:'Ayush E P', swethaswan:'Swethaswan' };
  for(const [key, name] of Object.entries(core)){
    if(creds['__removed_' + key]) continue;
    const entry = creds[key];
    const role  = entry?.role || 'engineer';
    if(role === 'engineer'){
      list.push({ key, name: entry?.name || name, username: entry?.username || key });
    }
  }
  // Dynamic engineers
  for(const [key, entry] of Object.entries(creds)){
    if(['admin','ayush','swethaswan'].includes(key)) continue;
    if(key.startsWith('__removed_')) continue;
    if(entry?.role === 'engineer'){
      list.push({ key, name: entry.name || key, username: entry.username || key });
    }
  }
  return list;
}

// ── PHASE 2: Build leave summary for a month ─────────────────
async function buildLeaveSummary(env, yearMonth){
  const engineers = await getEngineerList(env);
  const allLeaves = await env.PUSH_SUBS.get('leave_requests', {type:'json'}) || [];
  const quota     = await env.PUSH_SUBS.get('leave_quota',    {type:'json'}) || { personal:2, health:2 };

  const summary = [];
  for(const eng of engineers){
    // Filter leaves for this engineer in this month
    const engLeaves = allLeaves.filter(l =>
      l.user === eng.key &&
      inMonth(l.ts || l.fromDate, yearMonth)
    );

    let personal_taken  = 0;
    let personal_pending = 0;
    let health_taken    = 0;
    let health_pending  = 0;
    const reasons       = [];
    const leaveDetails  = [];

    for(const l of engLeaves){
      const days   = l.days || 1;
      const reason = l.reason || 'personal reasons';
      const isHealth = reason.toLowerCase().includes('health') || reason.toLowerCase().includes('medical') || reason.toLowerCase().includes('urgent');
      const type   = isHealth ? 'health' : 'personal';

      if(l.status === 'approved'){
        if(type === 'health')   health_taken   += days;
        else                    personal_taken += days;
      } else if(l.status === 'pending'){
        if(type === 'health')   health_pending   += days;
        else                    personal_pending += days;
      }

      if(reason && !reasons.includes(reason)) reasons.push(reason);
      leaveDetails.push({
        id:          l.id,
        subject:     l.subject || '',
        fromDate:    l.fromDate || '',
        toDate:      l.toDate   || '',
        days,
        reason,
        type,
        status:      l.status || 'pending',
        approvedBy:  l.approvedBy  || '',
        approvedAt:  l.approvedAt  || '',
        submittedAt: fmtDateTime(l.ts)
      });
    }

    summary.push({
      user:               eng.key,
      name:               eng.name,
      personal_taken,
      personal_pending,
      personal_remaining: Math.max(0, quota.personal - personal_taken),
      personal_quota:     quota.personal,
      health_taken,
      health_pending,
      health_remaining:   Math.max(0, quota.health - health_taken),
      health_quota:       quota.health,
      total_taken:        personal_taken + health_taken,
      reasons,
      details:            leaveDetails
    });
  }
  return { summary, quota };
}

// ── PHASE 2: Build visit summary for a month ─────────────────
async function buildVisitSummary(env, yearMonth){
  const engineers = await getEngineerList(env);
  const allVisits = await env.PUSH_SUBS.get('visit_requests', {type:'json'}) || [];

  const summary = [];
  for(const eng of engineers){
    const engVisits = allVisits.filter(v =>
      v.user === eng.key &&
      inMonth(v.ts, yearMonth)
    );

    const details = engVisits.map(v => ({
      id:          v.id,
      subject:     v.subject || '',
      type:        v.type    || 'approval',
      sites:       v.body    ? extractSitesFromBody(v.body) : [],
      submittedAt: fmtDateTime(v.ts),
      status:      v.status  || 'pending',
      approvedBy:  v.approvedBy || '',
      approvedAt:  v.approvedAt || ''
    }));

    summary.push({
      user:            eng.key,
      name:            eng.name,
      total_visits:    engVisits.length,
      approved:        engVisits.filter(v => v.status === 'approved').length,
      pending:         engVisits.filter(v => v.status === 'pending').length,
      details
    });
  }
  return { summary };
}

// Helper: extract site names from plain-text visit body
function extractSitesFromBody(body){
  const lines  = body.split('\n');
  const sites  = [];
  // Look for lines that look like site data rows (have | separators)
  for(const line of lines){
    const parts = line.split('|');
    if(parts.length >= 3){
      const siteName = parts[1]?.trim();
      if(siteName && siteName.length > 3 && !siteName.toUpperCase().includes('SITE LOCATION')){
        sites.push(siteName);
      }
    }
  }
  return sites;
}

// ── PHASE 2: Build alert summary for a month ─────────────────
async function buildAlertSummary(env, yearMonth){
  // Collect all inboxes for engineers and look for items sentBy admin
  const engineers  = await getEngineerList(env);
  const alertMap   = {}; // alertId → { title, body, sentAt, sentBy, recipients:{user→{acked,ackedAt}} }

  for(const eng of engineers){
    const inbox = await env.PUSH_SUBS.get('inbox:' + eng.key, {type:'json'}) || [];
    for(const item of inbox){
      if(!inMonth(item.sentAt, yearMonth)) continue;
      if(!item.id) continue;
      // Group by a shared alert ID — strip per-user suffix (_username)
      const baseId = item.id.replace(/_[^_]+$/, '');
      if(!alertMap[baseId]){
        alertMap[baseId] = {
          alertId:    baseId,
          title:      item.title  || '',
          body:       item.body   || '',
          sentAt:     item.sentAt || '',
          sentBy:     item.sentBy || 'admin',
          recipients: {}
        };
      }
      alertMap[baseId].recipients[eng.key] = {
        name:         eng.name,
        acknowledged: item.acknowledged  || false,
        acknowledgedAt: item.acknowledgedAt || null
      };
    }
  }

  const alerts = Object.values(alertMap).sort((a,b) => new Date(b.sentAt) - new Date(a.sentAt));

  // Enrich with counts
  for(const alert of alerts){
    const recips       = Object.values(alert.recipients);
    alert.total_sent   = recips.length;
    alert.total_acked  = recips.filter(r => r.acknowledged).length;
    alert.total_unacked= recips.length - alert.total_acked;
  }

  return { alerts };
}

// ── PHASE 2: CSV generators ───────────────────────────────────
function leavesToCsv(summary, yearMonth){
  const headers = [
    'Engineer','Month',
    'Personal Quota','Personal Taken','Personal Pending','Personal Remaining',
    'Health Quota','Health Taken','Health Pending','Health Remaining',
    'Total Taken','Reasons'
  ];
  const rows = summary.map(s => [
    s.name, yearMonth,
    s.personal_quota, s.personal_taken, s.personal_pending, s.personal_remaining,
    s.health_quota,   s.health_taken,   s.health_pending,   s.health_remaining,
    s.total_taken,
    s.reasons.join(' | ')
  ]);
  return buildCsv(headers, rows);
}

function leaveDetailsToCsv(summary, yearMonth){
  const headers = [
    'Engineer','Month','Subject','From Date','To Date','Days','Type','Reason',
    'Status','Approved By','Approved At','Submitted At'
  ];
  const rows = [];
  for(const s of summary){
    for(const d of s.details){
      rows.push([
        s.name, yearMonth, d.subject,
        d.fromDate ? fmtDate(d.fromDate) : '',
        d.toDate   ? fmtDate(d.toDate)   : '',
        d.days, d.type, d.reason, d.status,
        d.approvedBy, d.approvedAt ? fmtDateTime(d.approvedAt) : '',
        d.submittedAt
      ]);
    }
  }
  return buildCsv(headers, rows);
}

function visitsToCsv(summary, yearMonth){
  const headers = [
    'Engineer','Month','Total Requests','Approved','Pending'
  ];
  const rows = summary.map(s => [
    s.name, yearMonth, s.total_visits, s.approved, s.pending
  ]);
  return buildCsv(headers, rows);
}

function visitDetailsToCsv(summary, yearMonth){
  const headers = [
    'Engineer','Month','Subject','Type','Sites Visited',
    'Status','Approved By','Approved At','Submitted At'
  ];
  const rows = [];
  for(const s of summary){
    for(const d of s.details){
      rows.push([
        s.name, yearMonth, d.subject, d.type,
        d.sites.join(' | '),
        d.status, d.approvedBy,
        d.approvedAt ? fmtDateTime(d.approvedAt) : '',
        d.submittedAt
      ]);
    }
  }
  return buildCsv(headers, rows);
}

function alertsToCsv(alerts, yearMonth){
  const headers = [
    'Alert Title','Body','Sent At','Sent By',
    'Total Recipients','Acknowledged','Unacknowledged'
  ];
  const rows = alerts.map(a => [
    a.title, a.body,
    fmtDateTime(a.sentAt), a.sentBy,
    a.total_sent, a.total_acked, a.total_unacked
  ]);
  return buildCsv(headers, rows);
}

function alertDetailsToCsv(alerts, yearMonth){
  const headers = [
    'Alert Title','Sent At','Sent By','Engineer','Acknowledged','Acknowledged At'
  ];
  const rows = [];
  for(const a of alerts){
    for(const [user, rec] of Object.entries(a.recipients)){
      rows.push([
        a.title,
        fmtDateTime(a.sentAt),
        a.sentBy,
        rec.name || user,
        rec.acknowledged ? 'Yes' : 'No',
        rec.acknowledgedAt ? fmtDateTime(rec.acknowledgedAt) : ''
      ]);
    }
  }
  return buildCsv(headers, rows);
}

// ── HTTP handler ─────────────────────────────────────────────
async function handleRequest(request, env){
  const url     = new URL(request.url);
  const headers = {'Access-Control-Allow-Origin':'*', 'Content-Type':'application/json'};

  if(request.method === 'OPTIONS'){
    return new Response(null, {status:204, headers:{
      'Access-Control-Allow-Origin':'*',
      'Access-Control-Allow-Methods':'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers':'Content-Type, Authorization',
      'Access-Control-Max-Age':'86400'
    }});
  }

  // ── PHASE 2: Reporter summary endpoint ───────────────────────
  // GET /reporter-summary?month=YYYY-MM
  // Returns full JSON summary: leaves, visits, alerts for the month
  if(url.pathname === '/reporter-summary' && request.method === 'GET'){
    const month = url.searchParams.get('month') || new Date().toISOString().slice(0,7);
    // Validate month format
    if(!/^\d{4}-\d{2}$/.test(month)){
      return new Response(JSON.stringify({ok:false, error:'month must be YYYY-MM'}), {status:400, headers});
    }
    try{
      const [leaveData, visitData, alertData] = await Promise.all([
        buildLeaveSummary(env, month),
        buildVisitSummary(env, month),
        buildAlertSummary(env, month)
      ]);
      return new Response(JSON.stringify({
        ok:     true,
        month,
        leaves: leaveData,
        visits: visitData,
        alerts: alertData
      }), {headers});
    }catch(e){
      console.error('reporter-summary error:', e);
      return new Response(JSON.stringify({ok:false, error:e.message}), {status:500, headers});
    }
  }

  // ── PHASE 2: CSV download endpoint ───────────────────────────
  // GET /reporter-download?month=YYYY-MM&type=leaves|leave_details|visits|visit_details|alerts|alert_details|all
  // Returns CSV file as attachment download
  if(url.pathname === '/reporter-download' && request.method === 'GET'){
    const month    = url.searchParams.get('month') || new Date().toISOString().slice(0,7);
    const type     = url.searchParams.get('type')  || 'all';
    const csvHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type':                'text/csv;charset=utf-8',
      'Content-Disposition':         `attachment; filename="fieldmanager_${type}_${month}.csv"`,
      'Cache-Control':               'no-store'
    };

    if(!/^\d{4}-\d{2}$/.test(month)){
      return new Response('month must be YYYY-MM', {status:400, headers});
    }

    try{
      if(type === 'leaves'){
        const { summary } = await buildLeaveSummary(env, month);
        return new Response(leavesToCsv(summary, month), {headers:csvHeaders});
      }
      if(type === 'leave_details'){
        const { summary } = await buildLeaveSummary(env, month);
        return new Response(leaveDetailsToCsv(summary, month), {headers:csvHeaders});
      }
      if(type === 'visits'){
        const { summary } = await buildVisitSummary(env, month);
        return new Response(visitsToCsv(summary, month), {headers:csvHeaders});
      }
      if(type === 'visit_details'){
        const { summary } = await buildVisitSummary(env, month);
        return new Response(visitDetailsToCsv(summary, month), {headers:csvHeaders});
      }
      if(type === 'alerts'){
        const { alerts } = await buildAlertSummary(env, month);
        return new Response(alertsToCsv(alerts, month), {headers:csvHeaders});
      }
      if(type === 'alert_details'){
        const { alerts } = await buildAlertSummary(env, month);
        return new Response(alertDetailsToCsv(alerts, month), {headers:csvHeaders});
      }
      if(type === 'all'){
        // Build a single combined CSV with section separators
        const [leaveData, visitData, alertData] = await Promise.all([
          buildLeaveSummary(env, month),
          buildVisitSummary(env, month),
          buildAlertSummary(env, month)
        ]);
        const sections = [
          '=== LEAVE SUMMARY ===\r\n' + leavesToCsv(leaveData.summary, month),
          '\r\n\r\n=== LEAVE DETAILS ===\r\n' + leaveDetailsToCsv(leaveData.summary, month),
          '\r\n\r\n=== VISIT SUMMARY ===\r\n' + visitsToCsv(visitData.summary, month),
          '\r\n\r\n=== VISIT DETAILS ===\r\n' + visitDetailsToCsv(visitData.summary, month),
          '\r\n\r\n=== ALERT SUMMARY ===\r\n' + alertsToCsv(alertData.alerts, month),
          '\r\n\r\n=== ALERT DETAILS ===\r\n' + alertDetailsToCsv(alertData.alerts, month),
        ];
        const allHeaders = {
          ...csvHeaders,
          'Content-Disposition': `attachment; filename="fieldmanager_full_report_${month}.csv"`
        };
        return new Response(sections.join(''), {headers:allHeaders});
      }
      return new Response(JSON.stringify({ok:false, error:'Unknown type: ' + type}), {status:400, headers});
    }catch(e){
      console.error('reporter-download error:', e);
      return new Response(JSON.stringify({ok:false, error:e.message}), {status:500, headers});
    }
  }

  // POST /subscribe
  if(url.pathname === '/subscribe' && request.method === 'POST'){
    const body    = await request.json();
    const subs    = await env.PUSH_SUBS.get('subscriptions', {type:'json'}) || [];
    const filtered= subs.filter(s => s.user !== body.user);
    filtered.push({user:body.user, engineer:body.engineer, subscription:body.subscription});
    await env.PUSH_SUBS.put('subscriptions', JSON.stringify(filtered));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // POST /unsubscribe
  if(url.pathname === '/unsubscribe' && request.method === 'POST'){
    const body = await request.json();
    const subs = await env.PUSH_SUBS.get('subscriptions', {type:'json'}) || [];
    await env.PUSH_SUBS.put('subscriptions', JSON.stringify(subs.filter(s => s.user !== body.user)));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // POST /manual-alert
  if(url.pathname === '/manual-alert' && request.method === 'POST'){
    const reqBody    = await request.json();
    const {title, body:msgBody, recipients, sender} = reqBody;
    const alertTitle = title   || 'Alert from admin';
    const alertBody  = msgBody || '';
    if(!recipients || !recipients.length){
      return new Response(JSON.stringify({ok:false, error:'No recipients'}), {status:400, headers});
    }
    const subs       = await env.PUSH_SUBS.get('subscriptions', {type:'json'}) || [];
    const userEngMap = await buildUserEngMap(env);
    let sent         = 0;
    const sentAt     = new Date().toISOString();
    const alertId    = Date.now() + '_alert';
    for(const username of recipients){
      const engName = userEngMap[username];
      await appendToInbox(env, username, {
        id:             alertId + '_' + username,
        title:          alertTitle,
        body:           alertBody,
        sentAt,
        sentBy:         sender || 'admin',
        acknowledged:   false,
        acknowledgedAt: null
      });
      const sub = subs.find(s => s.user === username || s.engineer === engName);
      if(!sub){ console.log('No push sub for', username, '— inbox only'); continue; }
      try{
        await sendPush(sub.subscription, {title:alertTitle, body:alertBody, tag:'manual-alert-'+Date.now(), url:APP_URL});
        sent++;
      }catch(e){ console.error('Push failed for', username, e.message); }
    }
    return new Response(JSON.stringify({ok:true, sent, total:recipients.length}), {headers});
  }

  // POST /acknowledge-alert
  if(url.pathname === '/acknowledge-alert' && request.method === 'POST'){
    const body = await request.json();
    const {user, alertId, title} = body;
    if(!user || !alertId){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const key   = 'inbox:' + user;
    const inbox = await env.PUSH_SUBS.get(key, {type:'json'}) || [];
    let updated = false;
    inbox.forEach(n => {
      if(n.id === alertId){
        n.acknowledged   = true;
        n.acknowledgedAt = new Date().toISOString();
        updated = true;
      }
    });
    if(updated) await env.PUSH_SUBS.put(key, JSON.stringify(inbox));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /inbox?user=<username>
  if(url.pathname === '/inbox' && request.method === 'GET'){
    const username = url.searchParams.get('user');
    if(!username){
      return new Response(JSON.stringify({ok:false, error:'Missing user param'}), {status:400, headers});
    }
    const inbox = await env.PUSH_SUBS.get('inbox:' + username, {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, inbox}), {headers});
  }

  // POST /clear-inbox
  if(url.pathname === '/clear-inbox' && request.method === 'POST'){
    const body = await request.json();
    if(!body.user){
      return new Response(JSON.stringify({ok:false, error:'Missing user'}), {status:400, headers});
    }
    await env.PUSH_SUBS.put('inbox:' + body.user, JSON.stringify([]));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /get-credentials
  if(url.pathname === '/get-credentials' && request.method === 'GET'){
    const creds = await env.PUSH_SUBS.get('credentials', {type:'json'}) || {};
    return new Response(JSON.stringify({ok:true, credentials:creds}), {headers});
  }

  // POST /set-credentials
  if(url.pathname === '/set-credentials' && request.method === 'POST'){
    const body = await request.json();
    const {adminHash, credentials, removedKeys=[]} = body;
    if(!adminHash || !credentials){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const stored          = await env.PUSH_SUBS.get('credentials', {type:'json'}) || {};
    const expectedAdminHash = stored.admin?.hash || 'c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951';
    if(adminHash !== expectedAdminHash){
      return new Response(JSON.stringify({ok:false, error:'Unauthorised'}), {status:401, headers});
    }
    for(const [user, entry] of Object.entries(credentials)){
      if(!entry.username || entry.username.trim().length < 3){
        return new Response(JSON.stringify({ok:false, error:'Username too short for ' + user}), {status:400, headers});
      }
      if(!entry.hash || !/^[a-f0-9]{64}$/.test(entry.hash)){
        return new Response(JSON.stringify({ok:false, error:'Invalid hash for ' + user}), {status:400, headers});
      }
      if(entry.role && !isValidRole(entry.role)){
        return new Response(JSON.stringify({ok:false, error:'Invalid role for ' + user}), {status:400, headers});
      }
    }
    const updated = {...stored};
    for(const [user, entry] of Object.entries(credentials)){
      updated[user] = { username:entry.username.trim(), hash:entry.hash, role:entry.role||'engineer', name:entry.name||entry.username.trim() };
    }
    for(const key of removedKeys){
      if(key !== 'admin') delete updated[key];
    }
    await env.PUSH_SUBS.put('credentials', JSON.stringify(updated));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // POST /set-admin-password
  if(url.pathname === '/set-admin-password' && request.method === 'POST'){
    const body = await request.json();
    const {currentHash, newHash} = body;
    if(!currentHash || !newHash){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const stored       = await env.PUSH_SUBS.get('credentials', {type:'json'}) || {};
    const expectedHash = stored.admin?.hash || 'c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951';
    if(currentHash !== expectedHash){
      return new Response(JSON.stringify({ok:false, error:'Current password incorrect'}), {status:401, headers});
    }
    if(!/^[a-f0-9]{64}$/.test(newHash)){
      return new Response(JSON.stringify({ok:false, error:'Invalid hash'}), {status:400, headers});
    }
    // passwordChangedAt lets every signed-in device detect "this session predates
    // the current password" and force itself back to the login screen — this is
    // what implements "log out of all devices" for the admin account.
    const passwordChangedAt = Date.now();
    await env.PUSH_SUBS.put('credentials', JSON.stringify({...stored, admin:{username:'admin', hash:newHash, passwordChangedAt}}));
    return new Response(JSON.stringify({ok:true, passwordChangedAt}), {headers});
  }

  // POST /submit-report
  if(url.pathname === '/submit-report' && request.method === 'POST'){
    const body = await request.json();
    const {user, subject, type, ts} = body;
    const reportBody = body.reportBody || body.body || '';
    if(!user || !subject){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const reports = await env.PUSH_SUBS.get('reports', {type:'json'}) || [];
    reports.unshift({id:ts+'_'+user, user, subject, body:reportBody, type:type||'report', ts:ts||Date.now()});
    if(reports.length > 200) reports.length = 200;
    await env.PUSH_SUBS.put('reports', JSON.stringify(reports));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /get-reports
  if(url.pathname === '/get-reports' && request.method === 'GET'){
    const reports = await env.PUSH_SUBS.get('reports', {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, reports}), {headers});
  }

  // GET /get-contacts
  if(url.pathname === '/get-contacts' && request.method === 'GET'){
    const contacts = await env.PUSH_SUBS.get('mail_contacts', {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, contacts}), {headers});
  }

  // POST /set-contacts
  if(url.pathname === '/set-contacts' && request.method === 'POST'){
    const body = await request.json();
    if(!Array.isArray(body.contacts)){
      return new Response(JSON.stringify({ok:false, error:'contacts must be an array'}), {status:400, headers});
    }
    await env.PUSH_SUBS.put('mail_contacts', JSON.stringify(body.contacts));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // POST /submit-leave
  if(url.pathname === '/submit-leave' && request.method === 'POST'){
    const body = await request.json();
    if(!body.user || !body.subject){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const leaves   = await env.PUSH_SUBS.get('leave_requests', {type:'json'}) || [];
    const filtered = leaves.filter(l => l.id !== body.id);
    filtered.unshift({...body, status:body.status||'pending'});
    if(filtered.length > 500) filtered.length = 500;
    await env.PUSH_SUBS.put('leave_requests', JSON.stringify(filtered));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /get-leaves
  if(url.pathname === '/get-leaves' && request.method === 'GET'){
    const leaves = await env.PUSH_SUBS.get('leave_requests', {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, leaves}), {headers});
  }

  // POST /update-leave
  if(url.pathname === '/update-leave' && request.method === 'POST'){
    const body = await request.json();
    const {id, status, approvedBy} = body;
    if(!id || !status){
      return new Response(JSON.stringify({ok:false, error:'Missing id or status'}), {status:400, headers});
    }
    const leaves  = await env.PUSH_SUBS.get('leave_requests', {type:'json'}) || [];
    const updated = leaves.map(l => l.id === id ? {...l, status, approvedBy:approvedBy||'admin', approvedAt:new Date().toISOString()} : l);
    await env.PUSH_SUBS.put('leave_requests', JSON.stringify(updated));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /get-sites
  if(url.pathname === '/get-sites' && request.method === 'GET'){
    const sites = await env.PUSH_SUBS.get('distant_sites', {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, sites}), {headers});
  }

  // POST /set-sites
  if(url.pathname === '/set-sites' && request.method === 'POST'){
    const body = await request.json();
    if(!Array.isArray(body.sites)){
      return new Response(JSON.stringify({ok:false, error:'sites must be array'}), {status:400, headers});
    }
    await env.PUSH_SUBS.put('distant_sites', JSON.stringify(body.sites));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // POST /submit-visit
  if(url.pathname === '/submit-visit' && request.method === 'POST'){
    const body = await request.json();
    if(!body.user || !body.subject){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const visits = await env.PUSH_SUBS.get('visit_requests', {type:'json'}) || [];
    visits.unshift({...body, id:Date.now()+'_'+body.user, status:'pending'});
    if(visits.length > 300) visits.length = 300;
    await env.PUSH_SUBS.put('visit_requests', JSON.stringify(visits));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /get-visits
  if(url.pathname === '/get-visits' && request.method === 'GET'){
    const visits = await env.PUSH_SUBS.get('visit_requests', {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, visits}), {headers});
  }

  // POST /update-visit
  if(url.pathname === '/update-visit' && request.method === 'POST'){
    const body = await request.json();
    const {id, status, approvedBy} = body;
    if(!id || !status){
      return new Response(JSON.stringify({ok:false, error:'Missing id or status'}), {status:400, headers});
    }
    const visits  = await env.PUSH_SUBS.get('visit_requests', {type:'json'}) || [];
    const updated = visits.map(v => v.id === id ? {...v, status, approvedBy:approvedBy||'admin', approvedAt:new Date().toISOString()} : v);
    await env.PUSH_SUBS.put('visit_requests', JSON.stringify(updated));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /get-visit-contacts
  if(url.pathname === '/get-visit-contacts' && request.method === 'GET'){
    const type     = url.searchParams.get('type') || 'approval';
    const contacts = await env.PUSH_SUBS.get('visit_contacts_' + type, {type:'json'}) || [];
    return new Response(JSON.stringify({ok:true, contacts}), {headers});
  }

  // POST /set-visit-contacts
  if(url.pathname === '/set-visit-contacts' && request.method === 'POST'){
    const body = await request.json();
    const {type, contacts} = body;
    if(!type || !Array.isArray(contacts)){
      return new Response(JSON.stringify({ok:false, error:'Missing type or contacts'}), {status:400, headers});
    }
    await env.PUSH_SUBS.put('visit_contacts_' + type, JSON.stringify(contacts));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /device-list
  if(url.pathname === '/device-list' && request.method === 'GET'){
    const stored = await env.PUSH_SUBS.get('device_list', {type:'json'}) || {version:0, updatedAt:null, source:'none', fetchUrl:'', devices:[]};
    return new Response(JSON.stringify({ok:true, ...stored}), {headers});
  }

  // POST /device-list
  if(url.pathname === '/device-list' && request.method === 'POST'){
    const body = await request.json();
    if(!Array.isArray(body.devices)){
      return new Response(JSON.stringify({ok:false, error:'devices must be an array'}), {status:400, headers});
    }
    const payload = {version:body.version||Date.now(), updatedAt:new Date().toISOString(), source:body.source||'manual', fetchUrl:body.fetchUrl||'', devices:body.devices};
    await env.PUSH_SUBS.put('device_list', JSON.stringify(payload));
    return new Response(JSON.stringify({ok:true, count:body.devices.length}), {headers});
  }

  // POST /set-fetch-url
  if(url.pathname === '/set-fetch-url' && request.method === 'POST'){
    const body = await request.json();
    if(!body.url){ return new Response(JSON.stringify({ok:false, error:'Missing url'}), {status:400, headers}); }
    const stored = await env.PUSH_SUBS.get('device_list', {type:'json'}) || {version:0, devices:[]};
    stored.fetchUrl = body.url.trim();
    await env.PUSH_SUBS.put('device_list', JSON.stringify(stored));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /fetch-from-url
  if(url.pathname === '/fetch-from-url' && request.method === 'GET'){
    const stored   = await env.PUSH_SUBS.get('device_list', {type:'json'}) || {};
    const fetchUrl = stored.fetchUrl || '';
    if(!fetchUrl){ return new Response(JSON.stringify({ok:false, error:'No fetch URL configured'}), {status:400, headers}); }
    const tryUrls  = [fetchUrl];
    if(fetchUrl.startsWith('https://')) tryUrls.push(fetchUrl.replace('https://','http://'));
    let csvText    = null;
    for(const u of tryUrls){
      try{
        const r = await fetch(u, {headers:{'User-Agent':'Mozilla/5.0','Accept':'text/csv,text/plain,*/*'}, signal:AbortSignal.timeout(20000)});
        if(r.ok){ csvText = await r.text(); break; }
      }catch(e){ continue; }
    }
    if(!csvText){ return new Response(JSON.stringify({ok:false, error:'Could not fetch from URL'}), {status:502, headers}); }
    const lines   = csvText.split(/\r?\n/).filter(l => l.trim());
    if(lines.length < 2){ return new Response(JSON.stringify({ok:false, error:'CSV has no data rows'}), {status:422, headers}); }
    const hdr     = lines[0].split(',').map(h => h.replace(/^"|"$/g,'').trim().toLowerCase());
    const iSite   = hdr.findIndex(h => h.includes('location') || h.includes('site'));
    const iMac    = hdr.findIndex(h => h.includes('mac') || h.includes('device'));
    const iLabel  = hdr.findIndex(h => h.includes('label') || h.includes('position') || (h.includes('asset') && !h.includes('id')));
    const devices = [];
    for(let i = 1; i < lines.length; i++){
      const cols  = lines[i].split(',').map(c => c.replace(/^"|"$/g,'').trim());
      const site  = (iSite  >= 0 ? cols[iSite]  : cols[4] || '').trim();
      const mac   = (iMac   >= 0 ? cols[iMac]   : cols[0] || '').trim().toUpperCase();
      const label = (iLabel >= 0 ? cols[iLabel] : '').trim();
      if(!site || !mac) continue;
      devices.push({site, mac, assetId:label, label});
    }
    const payload = {version:Date.now(), updatedAt:new Date().toISOString(), source:'url_fetch', fetchUrl, devices};
    await env.PUSH_SUBS.put('device_list', JSON.stringify(payload));
    return new Response(JSON.stringify({ok:true, count:devices.length, ...payload}), {headers});
  }

  // POST /gmail-draft
  if(url.pathname === '/gmail-draft' && request.method === 'POST'){
    try{
      const body = await request.json();
      const {scriptUrl, ...payload} = body;
      if(!scriptUrl){ return new Response(JSON.stringify({ok:false, error:'No scriptUrl provided'}), {status:400, headers}); }
      const r    = await fetch(scriptUrl, {method:'POST', redirect:'follow', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
      const text = await r.text();
      if(text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html')){
        return new Response(JSON.stringify({ok:false, error:'Apps Script returned HTML — check deployment settings'}), {status:502, headers});
      }
      let result;
      try{ result = JSON.parse(text); }catch(e){ result = {ok:false, error:text.slice(0,200)}; }
      return new Response(JSON.stringify(result), {headers});
    }catch(e){
      return new Response(JSON.stringify({ok:false, error:e.message}), {status:502, headers});
    }
  }

  // GET /get-leave-quota
  if(url.pathname === '/get-leave-quota' && request.method === 'GET'){
    const quota = await env.PUSH_SUBS.get('leave_quota', {type:'json'}) || {personal:2, health:2};
    return new Response(JSON.stringify({ok:true, quota}), {headers});
  }

  // POST /set-leave-quota
  if(url.pathname === '/set-leave-quota' && request.method === 'POST'){
    const body = await request.json();
    const {adminHash, quota} = body;
    if(!adminHash || !quota){
      return new Response(JSON.stringify({ok:false, error:'Missing fields'}), {status:400, headers});
    }
    const stored       = await env.PUSH_SUBS.get('credentials', {type:'json'}) || {};
    const expectedHash = stored.admin?.hash || 'c2bc3a7a8e9ce3e9f6a922eb2efe8489bb67a5c4df099c6ce01a182916619951';
    if(adminHash !== expectedHash){
      return new Response(JSON.stringify({ok:false, error:'Unauthorised'}), {status:401, headers});
    }
    if(typeof quota.personal !== 'number' || typeof quota.health !== 'number'){
      return new Response(JSON.stringify({ok:false, error:'quota values must be numbers'}), {status:400, headers});
    }
    await env.PUSH_SUBS.put('leave_quota', JSON.stringify({personal:quota.personal, health:quota.health}));
    return new Response(JSON.stringify({ok:true}), {headers});
  }

  // GET /check-subs
  if(url.pathname === '/check-subs' && request.method === 'GET'){
    const subs    = await env.PUSH_SUBS.get('subscriptions', {type:'json'}) || [];
    const summary = subs.map(s => ({user:s.user, engineer:s.engineer, endpoint:s.subscription?.endpoint?.substring(0,80)+'...', hasKeys:!!(s.subscription?.keys)}));
    return new Response(JSON.stringify({ok:true, count:subs.length, subscribers:summary}, null, 2), {headers});
  }

  // GET /clear-subs
  if(url.pathname === '/clear-subs' && request.method === 'GET'){
    await env.PUSH_SUBS.put('subscriptions', JSON.stringify([]));
    return new Response(JSON.stringify({ok:true, message:'All subscriptions cleared'}), {headers});
  }

  return new Response(JSON.stringify({error:'Not found', path:url.pathname}), {status:404, headers});
}

// ── Entry point ───────────────────────────────────────────────
export default {
  async fetch(request, env){
    return handleRequest(request, env);
  }
};
