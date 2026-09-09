/* Real browser custody and scoped HTTP flow. Invoked by the synthetic bridge. */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';

const MAX_REQUEST_BYTES = 256 * 1024;
const failCapture = code => { const error = new Error('Request observation rejected'); error.code = code; throw error; };
// Independent observation encoding: Python's compact, sorted ensure_ascii JSON
// for the browser command subset. It never signs or retains a request value.
function canonicalPacket(value) {
  let nodes = 0;
  function encode(v, depth = 0) {
    if (++nodes > 12000 || depth > 24) failCapture('invalid_request_document');
    if (v === null || typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v) || Object.is(v, -0)) failCapture('invalid_request_document');
      return String(v);
    }
    if (typeof v === 'string') {
      if ([...v].some(c => c.codePointAt(0) >= 0xd800 && c.codePointAt(0) <= 0xdfff)) failCapture('invalid_request_document');
      return JSON.stringify(v).replace(/[\u007f-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`);
    }
    if (Array.isArray(v)) return `[${v.map(item=>encode(item,depth+1)).join(',')}]`;
    if (!v || typeof v !== 'object') failCapture('invalid_request_document');
    const ordered = Object.keys(v).sort((a,b)=>{
      const left=[...a].map(c=>c.codePointAt(0)), right=[...b].map(c=>c.codePointAt(0));
      for(let i=0;i<Math.min(left.length,right.length);i++) if(left[i]!==right[i]) return left[i]-right[i];
      return left.length-right.length;
    });
    return `{${ordered.map(key=>`${encode(key,depth+1)}:${encode(v[key],depth+1)}`).join(',')}}`;
  }
  return encode(value);
}
function checkPrivateFields(value, depth=0) {
  if(depth>24) failCapture('invalid_request_document');
  if(typeof value==='string' && /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(value)) failCapture('private_material_field_in_request');
  if(!value||typeof value!=='object') return;
  for(const [key,item]of Object.entries(value)) {
    const normalized=key.toLowerCase().replace(/[^a-z0-9]/g,'');
    if(/^(privatekey|privatekeyhex|privatekeyseed|seedphrase|seedhex|seed|pkcs8|passphrase|password|secretkey|signingkey)$/.test(normalized)
        || (key==='d' && typeof value.kty==='string')) failCapture('private_material_field_in_request');
    checkPrivateFields(item,depth+1);
  }
}
function publicRoute(pathname) {
  if(['/', '/register', '/submit', '/api/v1/seeds', '/api/v1/agents/challenge', '/api/v1/agents/verify',
      '/api/v1/agents/me/home', '/api/v1/browser/session', '/api/v1/browser/session/challenge',
      '/api/v1/browser/session/verify', '/api/v1/browser/session/logout', '/api/v1/witness-events'].includes(pathname)) return pathname;
  if(/^\/static\/[^/]+$/.test(pathname)) return '/static/:asset';
  if(/^\/schemas\/[^/]+$/.test(pathname)) return '/schemas/:schema';
  if(/^\/claims\/[^/]+$/.test(pathname)) return '/claims/:seed_id';
  if(/^\/agent\/[^/]+$/.test(pathname)) return '/agent/:subject_id';
  const seed=/^\/api\/v1\/seeds\/[^/]+(?:\/(chain|challenges|dossier))?$/.exec(pathname);
  if(seed) return '/api/v1/seeds/:seed_id'+(seed[1]?'/'+seed[1]:'');
  return '/unrecognized';
}
function observeRequest(request, expectedOrigin, elapsed) {
  const row={method:['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].includes(request.method)?request.method:'OTHER',
    route:'/unrecognized', origin_relation:'other-origin', resource_type:['document','stylesheet','image','media','font','script','texttrack','xhr','fetch','eventsource','websocket','manifest'].includes(request.resource_type)?request.resource_type:'other',
    elapsed_ms:Math.max(0,Math.floor(elapsed))};
  try {
    const url=new URL(request.url);
    row.route=publicRoute(url.pathname); row.origin_relation=url.origin===expectedOrigin?'same-origin':'other-origin';
    if(row.resource_type==='script' && row.origin_relation!=='same-origin') failCapture('other_origin_executable_request');
    if(request.body!==null && request.body!==undefined && request.body!=='') {
      if(typeof request.body!=='string'||Buffer.byteLength(request.body)>MAX_REQUEST_BYTES) failCapture('invalid_request_document');
      const value=JSON.parse(request.body);
      checkPrivateFields(value);
      // Client commands are already canonical. This equality also detects
      // duplicate members which JSON.parse would otherwise silently discard.
      if(canonicalPacket(value)!==request.body) failCapture('noncanonical_request_document');
      if(row.method==='POST' && (row.route==='/api/v1/seeds'||row.route==='/api/v1/seeds/:seed_id/challenges')) {
        if(row.origin_relation!=='same-origin') failCapture('other_origin_command');
        const kind=row.route==='/api/v1/seeds'?'seed':'challenge', packet=value[`${kind}_packet`];
        const identifier=packet?.[`${kind}_id`];
        if(typeof identifier!=='string'||!(kind==='seed'?/^sab_seed_[A-Za-z0-9_.:-]{3,128}$/:/^sab_challenge_[A-Za-z0-9_.:-]{3,128}$/).test(identifier)
            ||packet.schema!==`sab.${kind}_packet.v1`) failCapture('invalid_public_packet_identity');
        row.packet={kind,identifier,canonical_sha256:createHash('sha256').update(canonicalPacket(packet)).digest('hex')};
      }
    }
  } catch(error) {
    row.sanitizer_error=['private_material_field_in_request','invalid_request_document','noncanonical_request_document',
      'other_origin_executable_request','other_origin_command','invalid_public_packet_identity'].includes(error.code)?error.code:'invalid_request_document';
  }
  return row;
}
function sanitizerRegression() {
  const sentinel='SYNTHETIC_SECRET_SENTINEL_NEVER_PERSIST', origin='http://127.0.0.1:8123';
  const capture=(body,url='/api/v1/browser/session/logout')=>observeRequest({method:'POST',url:origin+url,resource_type:'fetch',body},origin,12.8);
  const csrf=capture(canonicalPacket({csrf_token:sentinel}),'/api/v1/browser/session/logout?csrf_token='+sentinel);
  assert.deepEqual(Object.keys(csrf).sort(),['elapsed_ms','method','origin_relation','resource_type','route'].sort());
  const privateField=capture(canonicalPacket({nested:{privateKey:sentinel}}));
  assert.equal(privateField.sanitizer_error,'private_material_field_in_request');
  const duplicate=capture(`{"nested":{"privateKey":"${sentinel}"},"nested":{}}`);
  assert.equal(duplicate.sanitizer_error,'noncanonical_request_document');
  const malformed=capture(`{"privateKey":"${sentinel}`);
  assert.equal(malformed.sanitizer_error,'invalid_request_document');
  const packet={schema:'sab.seed_packet.v1',seed_id:'sab_seed_sanitizer',claim:{text:sentinel},'😀':'astral','\uffff':'bmp'};
  const publicPacket=capture(canonicalPacket({seed_packet:packet}),'/api/v1/seeds');
  assert.equal(publicPacket.packet.canonical_sha256,createHash('sha256').update(canonicalPacket(packet)).digest('hex'));
  const failure={complete:false,requests:[csrf,privateField,duplicate,malformed,publicPacket],failure:{code:'browser_rehearsal_failed'}};
  const output=JSON.stringify(failure);
  assert.ok(!output.includes(sentinel)); assert.ok(!output.includes('csrf_token')); assert.ok(!output.includes('privateKey'));
  assert.ok(failure.requests.every(row=>!Object.hasOwn(row,'body')&&!Object.hasOwn(row,'url')));
}
sanitizerRegression();
if(process.argv.includes('--test-sanitizer')) {
  process.stdout.write(JSON.stringify({complete:true,check:'request_and_failure_sentinel_not_persisted'})+'\n');
  process.exit(0);
}
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.SAB_PLAYWRIGHT_MODULE || 'playwright');
const inputLines = readline.createInterface({input:process.stdin});
const lines = inputLines[Symbol.asyncIterator]();
async function reply() { const next = await lines.next(); assert.equal(next.done,false); const result = JSON.parse(next.value); assert.equal(result.ok,true); return result; }
async function bridge(request) { process.stdout.write(JSON.stringify(request)+'\n'); return reply(); }
const ready = await reply(), origin = ready.origin;
assert.equal(origin,process.env.SAB_REHEARSAL_ORIGIN);
const output = process.env.SAB_REHEARSAL_OUTPUT_DIR;
const observations = {schema:'sab.browser_rehearsal_observation.v2',complete:false,checks:[],requests:[],errors:[],snapshots:[],
  request_body_custody:'memory_only',packet_digest_canonicalization:'json-sort-keys-compact-v1',sanitizer_regression_passed:true};
const startedAt=performance.now();
const owned = new Set();
const check = name => observations.checks.push(name);
let page;
async function context(name, viewport={width:1440,height:1000}) {
  const result = await chromium.launchPersistentContext(path.join(output,`profile-${name}`),{headless:true,viewport});
  owned.add(result);
  result.on('request', request => {
    // Body exists only for synchronous inspection/hash computation. Never put
    // it, a header, a query string, or an exception payload in observations.
    const row=observeRequest({method:request.method(),url:request.url(),resource_type:request.resourceType(),body:request.postData()},origin,performance.now()-startedAt);
    if(row.sanitizer_error) observations.errors.push(row.sanitizer_error);
    observations.requests.push(row);
  });
  result.on('page', observePage);
  result.pages().forEach(observePage);
  return result;
}
function observePage(value) {
  value.on('pageerror', () => observations.errors.push('browser_page_error'));
}
async function statusIncludes(text) {
  await page.waitForFunction(expected => document.getElementById('participant-status')?.textContent.includes(expected),text,{timeout:10000});
}
async function click(id,text) { await page.locator(`#${id}`).click(); await statusIncludes(text); }
async function enroll(name, operator, probeCookie = false) {
  await page.goto(origin+'/register');
  await statusIncludes('Ready to retain');
  const before = observations.requests.filter(row=>row.method==='POST').length;
  await page.locator('#display_name').fill(name);
  await page.locator('#operator_id').fill(operator);
  await page.locator('#disclosure').fill('Synthetic browser rehearsal; no independent operator acceptance.');
  await page.locator('[name=retain_ack]').check();
  await page.getByRole('button',{name:'Retain key in this browser',exact:true}).click();
  await statusIncludes('Key retained.');
  assert.equal(observations.requests.filter(row=>row.method==='POST').length,before);
  const subject = await page.locator('#participant-subject').textContent();
  assert.match(subject,/^agent_ed25519_[0-9a-f]{32}$/);
  await click('participant-enroll','Control proved.');
  if (probeCookie) {
    await page.route('**/api/v1/browser/session/verify', async route => {
      const request = route.request();
      const response = await fetch(request.url(), {method:'POST',headers:await request.allHeaders(),body:request.postDataBuffer(),redirect:'error'});
      await route.fulfill({status:response.status,contentType:'application/json',body:await response.text()});
    });
    await click('participant-signin','did not retain its session cookie');
    assert.equal(await page.locator('#participant-session').isVisible(),false);
    assert.equal((await page.context().cookies()).filter(cookie=>cookie.name==='sab_web_session').length,0);
    await page.unroute('**/api/v1/browser/session/verify');
    check('A valid proof response without its cookie cannot display signed-in success');
  }
  await click('participant-signin','Signed in for six hours.');
  assert.equal(await page.evaluate(()=>document.cookie),'');
  return subject;
}
async function capture(label) {
  const metrics = await page.evaluate(()=>({width:innerWidth,documentWidth:document.documentElement.scrollWidth,
    inputs:[...document.querySelectorAll('.participant input:not([type=checkbox]),.participant textarea,.participant select')].filter(x=>x.getClientRects().length).map(x=>({id:x.id,font:getComputedStyle(x).fontSize,height:x.getBoundingClientRect().height})),
    buttons:[...document.querySelectorAll('.participant button')].filter(x=>x.getClientRects().length).map(x=>({id:x.id,disabled:x.disabled,color:getComputedStyle(x).color,background:getComputedStyle(x).backgroundColor,height:x.getBoundingClientRect().height}))}));
  assert.equal(metrics.documentWidth,metrics.width);
  assert.ok(metrics.inputs.every(row=>parseFloat(row.font)>=16 && row.height>=44));
  assert.ok(metrics.buttons.every(row=>row.height>=44));
  await page.screenshot({path:path.join(output,`${label}.png`),fullPage:true});
  observations.snapshots.push({label,...metrics});
}
try {
  let claimant = await context('claimant'); page = claimant.pages()[0];
  const subject = await enroll('Synthetic claimant 日本語','synthetic-browser-claimant',true);
  check('Retained non-server key, explicit enrollment and HttpOnly session');
  const localKeys = await page.evaluate(async()=>{
    const dbs = await indexedDB.databases(); const results=[];
    for (const item of dbs) {
      const db=await new Promise((resolve,reject)=>{const r=indexedDB.open(item.name);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
      for(const name of db.objectStoreNames) {
        const values=await new Promise((resolve,reject)=>{const r=db.transaction(name).objectStore(name).getAll();r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
        async function visit(v) { if(v instanceof CryptoKey){if(v.type==='private'){let exportDenied=false;try{await crypto.subtle.exportKey('pkcs8',v);}catch{exportDenied=true;}results.push({algorithm:v.algorithm.name,type:v.type,extractable:v.extractable,exportDenied});}}else if(v&&typeof v==='object'){for(const child of Object.values(v))await visit(child);} }
        for(const value of values)await visit(value);
      } db.close();
    } return results;
  });
  assert.ok(localKeys.length>0 && localKeys.every(key=>key.algorithm==='Ed25519'&&!key.extractable&&key.exportDenied));
  observations.localKeyProperties=localKeys; check('Persisted CryptoKey denies private export');
  await claimant.close(); owned.delete(claimant);
  claimant = await context('claimant'); page=claimant.pages()[0]; await page.goto(origin+'/register');
  await statusIncludes('Signed in.'); assert.equal(await page.locator('#participant-subject').textContent(),subject);
  check('Browser process restart preserves key and session');
  await bridge({operation:'restart'}); await page.reload(); await statusIncludes('Signed in.');
  check('Server process restart preserves accepted session');
  await page.goto(origin+'/submit'); await statusIncludes('No current grant.');
  assert.equal(await page.locator('#claim-title').isDisabled(),true);
  check('Proved identity and session do not mint submission permission');
  const seed='sab_seed_browser_custody';
  await bridge({operation:'grant',subject_id:subject,seed_id:seed,actions:['submit_seed']});
  await click('participant-refresh','Current grants are listed');
  await page.route('**/api/v1/agents/me/home?*',route=>route.fulfill({status:503,contentType:'application/json',body:'{"detail":"Synthetic observation unavailable"}'}));
  await click('participant-refresh','cannot admit another operation');
  assert.equal(await page.locator('#claim-title').isDisabled(),true);
  assert.equal(await page.locator('#claim-grant').inputValue(),'');
  assert.equal(await page.locator('#claim-review').isVisible(),false);
  await page.unroute('**/api/v1/agents/me/home?*');
  await click('participant-refresh','Current grants are listed');
  assert.equal(await page.locator('#claim-title').isDisabled(),false);
  check('Failed grant refresh clears stale permission; fresh observation recovers');
  for(const [id,value] of Object.entries({'claim-title':'A browser key is distinct from authority','claim-text':'A retained signing key and accepted session alone cannot authorize a scoped SAB contribution.','claim-scope':'Synthetic local browser rehearsal only','claim-context':'Whether an authenticated participant can submit without a separate grant','claim-success':'An exact grant permits the matching signed contribution.','claim-failure':'The same identity can submit before a grant exists.','claim-objection':'A public profile might be mistaken for delegated permission.','claim-evidence':'test://browser/session-does-not-grant-authority','claim-due':new Date(Date.now()+30*86400000).toISOString().slice(0,10)}))await page.locator(`#${id}`).fill(value);
  const beforeReview=observations.requests.filter(row=>row.method==='POST').length;
  await page.getByRole('button',{name:'Review claim before signing',exact:true}).click();
  await statusIncludes('Nothing has been signed');
  assert.equal(observations.requests.filter(row=>row.method==='POST').length,beforeReview);
  await capture('desktop-claim-review');
  await click('claim-sign','Your signed claim is recorded.');
  check('Explicit review precedes signed v1 seed with separate exact grant');
  await page.locator('#claim-result a').click();
  assert.equal(await page.locator('[aria-label="Exact submitted claim"]').textContent(),'A retained signing key and accepted session alone cannot authorize a scoped SAB contribution.');
  const second = await context('reviewer',{width:390,height:844}); page=second.pages()[0];
  const reviewer=await enroll('Synthetic reviewer العربية','synthetic-browser-reviewer');
  await capture('mobile-key');
  await bridge({operation:'grant',subject_id:reviewer,seed_id:seed,actions:['submit_challenge','submit_witness_event']});
  await page.goto(origin+`/claims/${seed}`); await page.locator('#contribute > summary').click();
  await statusIncludes('Current grants are listed');
  await page.locator('#challenge-quote').fill('accepted session alone cannot authorize');
  await page.locator('#challenge-argument').fill('Narrow this claim to the exact configured origin and current database transaction.');
  await page.locator('#challenge-evidence').fill('test://browser/current-origin-counterexample');
  await page.getByRole('button',{name:'Review challenge',exact:true}).click(); await statusIncludes('Review the exact target');
  await click('contribution-sign','Observation recorded.');
  check('Second synthetic browser submits a scoped signed challenge');
  await page.locator('#witness-action').selectOption('refuse');
  await page.locator('#witness-note').fill('I inspected the synthetic browser trace; broader cross-origin and storage rollback claims remain unsupported.');
  await page.getByRole('button',{name:'Review witness observation',exact:true}).click(); await statusIncludes('Review the exact target');
  await capture('mobile-witness-review');
  await click('contribution-sign','Observation recorded.');
  check('Second synthetic browser signs exact current-chain witness intent');
  page=claimant.pages()[0]; await page.goto(origin+'/register'); await statusIncludes('Signed in.');
  await click('participant-signout','Signed out.');
  await click('participant-signin','Signed in for six hours.');
  await page.getByText('Rotate or retire this key',{exact:true}).click(); await page.locator('#retire-ack').check(); await click('participant-rotate','Key rotated.');
  const successor=await page.locator('#participant-subject').textContent(); assert.notEqual(successor,subject);
  await click('participant-signin','Signed in for six hours.');
  await page.goto(origin+'/submit'); await statusIncludes('No current grant.');
  check('Rotation preserves successor custody and transfers no grants');
  await page.goto(origin+'/register'); await statusIncludes('Signed in.'); await page.getByText('Rotate or retire this key',{exact:true}).click(); await page.locator('#retire-ack').check();
  await click('participant-revoke','Key retired on this instance.');
  assert.equal(await page.locator('#participant-session').isVisible(),false);
  check('Retirement invalidates session immediately');
  for(const row of observations.requests) {
    if(row.resource_type==='script')assert.equal(row.origin_relation,'same-origin');
    assert.equal(row.sanitizer_error,undefined);
  }
  check('Only same-origin executable requests; no private-material fields in HTTP commands');
  assert.deepEqual(observations.errors,[]);
  observations.complete=true;
} catch {
  observations.failure={code:'browser_rehearsal_failed',last_completed_check:observations.checks.at(-1)??null};
  process.exitCode=1;
} finally {
  for(const item of owned)await item.close().catch(()=>{});
  await fs.writeFile(path.join(output,'browser-observations.json'),JSON.stringify(observations,null,2));
  inputLines.close(); process.stdin.destroy();
}
