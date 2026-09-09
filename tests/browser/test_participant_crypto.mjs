// Run with Node 22: node --test tests/browser/test_participant_crypto.mjs
// Optional live Python parity: SAB_TEST_PYTHON=<repo test Python> node --test ...
// This storage double exercises transaction/custody decisions with real
// structured-cloned CryptoKeys. Chromium integration separately tests IndexedDB.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const source = await readFile(new URL('../../agora/static/participant_crypto.js', import.meta.url), 'utf8');
const {canonicalJSON, parseStrictJSON, hashCanonical, validateKeyChallenge, validateSessionChallenge, createParticipant, ParticipantError}
  = await import(`data:text/javascript;base64,${Buffer.from(`${source}\n//# sourceURL=participant_crypto.js\n`).toString('base64')}`);
const fixture = JSON.parse(await readFile(new URL('./participant_protocol_fixture.json', import.meta.url), 'utf8'));
const ORIGIN = 'http://localhost:8123';
const NONE = {authority_effect: 'none', standing_effect: 'none'};
const CANON = 'json-sort-keys-compact-v1';
const clone = (v) => structuredClone(v);
const bytes = (v) => new TextEncoder().encode(canonicalJSON(v));
const fromHex = (v) => Buffer.from(v, 'hex');
const hex = (v) => Buffer.from(v).toString('hex');
const subjectFor = async (publicKey) => `agent_ed25519_${hex(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(publicKey))).slice(0, 32)}`;
const jsonResponse = (value) => new Response(JSON.stringify(value), {headers: {'Content-Type': 'application/json'}});
const rawResponse = (value) => new Response(value, {headers: {'Content-Type': 'application/json'}});
const rejects = (operation, code) => assert.rejects(operation, (e) => e instanceof ParticipantError && (!code || e.code === code));

function memoryIDB() {
  let row, failWrite = false, writes = 0;
  const queue = [];
  let running = false;
  function next() {
    if (running || !queue.length) return;
    running = true;
    const start = queue.shift();
    setImmediate(() => start(() => { running = false; next(); }));
  }
  const db = {
    objectStoreNames: {contains: () => true}, close() {},
    transaction() {
      const operations = [];
      let finished = false, active = false, working, release;
      const tx = {
        objectStore: () => ({
          get: () => {
            const request = {};
            operations.push(() => { request.result = clone(working); request.onsuccess?.(); });
            return request;
          },
          put: (value) => {
            const saved = clone(value);
            operations.push(() => { writes++; if (failWrite === true || failWrite === writes) tx.abort(); else working = saved; });
          },
        }),
        abort() { if (!finished) { finished = true; setImmediate(() => tx.onabort?.()); if (active) release(); } },
      };
      const pump = () => {
        if (finished) return;
        const op = operations.shift();
        if (op) { op(); setImmediate(pump); }
        else { row = clone(working); finished = true; tx.oncomplete?.(); release(); }
      };
      queue.push((done) => { active = true; release = done; working = clone(row); pump(); });
      next();
      return tx;
    },
  };
  return {
    open() { const request = {}; setImmediate(() => { request.result = db; request.onsuccess?.(); }); return request; },
    snapshot: () => clone(row),
    failWrites: (value) => { failWrite = value; },
  };
}

function environment() {
  const storage = memoryIDB();
  const calls = {sign: 0, generate: 0, fetch: []};
  const subtle = new Proxy(webcrypto.subtle, {get(target, key) {
    const value = target[key];
    if (typeof value !== 'function') return value;
    return (...args) => { if (key === 'sign') calls.sign++; if (key === 'generateKey') calls.generate++; return value.apply(target, args); };
  }});
  for (const [key, value] of Object.entries({
    location: {origin: ORIGIN}, isSecureContext: true, indexedDB: storage, navigator: {},
    crypto: {subtle, getRandomValues: webcrypto.getRandomValues.bind(webcrypto)},
    fetch: async (...args) => { calls.fetch.push(args); throw new Error('No test server configured'); },
  })) Object.defineProperty(globalThis, key, {configurable: true, writable: true, value});
  return {storage, calls};
}

async function identityFor(registration, createdAt) {
  const subject = await subjectFor(registration.public_key);
  return {schema: 'sab.agent_identity.v1', subject_id: subject, identity_ref: `sab_identity_${subject}`,
    display_name: registration.display_name, identity_rail: 'ed25519', public_key: registration.public_key,
    controller: registration.controller, operator_backing: clone(registration.operator_backing), external_attestations: [],
    created_at: createdAt, revocation_status: 'active', evidence_refs: [`web_agents:${subject}`]};
}

async function verify(publicKey, signature, message) {
  const key = await webcrypto.subtle.importKey('raw', fromHex(publicKey), 'Ed25519', false, ['verify']);
  return webcrypto.subtle.verify('Ed25519', key, fromHex(signature), bytes(message));
}

function fakeServer(env) {
  let sequence = 0, currentSession = null;
  const identities = new Map(), bindings = new Map(), challenges = new Map();
  const state = {tamper: null, fail: null, before: null, captures: [], identities, bindings};
  const binding = (identity, status, proofId, at, successor = null) => ({schema: 'sab.key_control_binding.v1',
    subject_id: identity.subject_id, public_key: identity.public_key, status, proof_id: proofId, proved_at: at,
    successor_subject_id: successor, scope: 'key_control_only', ...NONE});
  globalThis.fetch = async (url, options) => {
    env.calls.fetch.push([url, options]);
    assert.equal(options.credentials, 'same-origin'); assert.equal(options.mode, 'same-origin'); assert.equal(options.redirect, 'error');
    assert.equal(new URL(url).origin, ORIGIN);
    assert.ok(!options.body || !/privateKey|private_key|secret|pkcs8|seed_hex/.test(options.body));
    const path = new URL(url).pathname, body = options.body ? JSON.parse(options.body) : undefined;
    if (state.before) await state.before(path, body);
    if (state.fail?.(path, body)) throw new Error('Synthetic connection loss');
    if (path === '/api/v1/agents/challenge') {
      const created = new Date().toISOString(), identity = body.registration ? await identityFor(body.registration, created) : null;
      const old = body.action === 'register' ? identity : identities.get(body.subject_id);
      const message = {schema: 'sab.key_control_message.v1', action: body.action, audience: ORIGIN, method: 'POST',
        path: '/api/v1/agents/verify', challenge_id: `sab_kc_challenge_${(++sequence).toString(16).padStart(32, '0')}`,
        nonce: 'ab'.repeat(32), subject_id: old.subject_id, public_key: old.public_key, issued_at: created,
        expires_at: new Date(Date.parse(created) + 120000).toISOString(), proposed_identity: identity,
        proposed_identity_sha256: identity ? await hashCanonical(identity) : null};
      challenges.set(message.challenge_id, clone(message));
      const envelope = {schema: 'sab.key_control_challenge.v1', message, signature_algorithm: 'ed25519', canonicalization: CANON, ...NONE};
      if (state.tamper) await state.tamper(envelope);
      return jsonResponse(envelope);
    }
    if (path === '/api/v1/agents/verify') {
      const message = challenges.get(body.challenge_id);
      assert.ok(await verify(message.public_key, body.signature, message));
      if (message.action === 'rotate') assert.ok(await verify(message.proposed_identity.public_key, body.successor_signature, message));
      else assert.deepEqual(Object.keys(body).sort(), ['challenge_id', 'signature']);
      state.captures.push({public_key: message.public_key, signature: body.signature, message: clone(message)});
      challenges.delete(body.challenge_id);
      const identity = message.action === 'revoke' ? {...identities.get(message.subject_id), revocation_status: 'revoked'} : message.proposed_identity;
      const at = new Date().toISOString(), proofId = `sab_kc_proof_${sequence.toString(16).padStart(32, '0')}`;
      const next = binding(identity, identity.revocation_status, proofId, at);
      identities.set(identity.subject_id, identity); bindings.set(identity.subject_id, next);
      let previous = null;
      if (message.action === 'rotate') {
        const old = {...identities.get(message.subject_id), revocation_status: 'superseded'};
        previous = binding(old, 'superseded', proofId, at, identity.subject_id);
        identities.set(old.subject_id, old); bindings.set(old.subject_id, previous);
      }
      return jsonResponse({schema: 'sab.key_control_result.v1', action: message.action, challenge_id: message.challenge_id,
        proof_id: proofId, verified_at: at, identity, binding: next, previous_binding: previous, ...NONE});
    }
    if (path === '/api/v1/browser/session/challenge') {
      const identity = identities.get(body.subject_id);
      assert.deepEqual(Object.keys(body), ['subject_id']);
      const created = new Date().toISOString();
      const message = {schema: 'sab.browser_session_message.v1', action: 'open_session', audience: ORIGIN, method: 'POST',
        path: '/api/v1/browser/session/verify', challenge_id: `sab_browser_challenge_${(++sequence).toString(16).padStart(32, '0')}`,
        nonce: 'cd'.repeat(32), subject_id: identity.subject_id, public_key: identity.public_key,
        issued_at: created, expires_at: new Date(Date.parse(created) + 120000).toISOString()};
      challenges.set(message.challenge_id, clone(message));
      const envelope = {schema: 'sab.browser_session_challenge.v1', message, signature_algorithm: 'ed25519', canonicalization: CANON, ...NONE};
      if (state.tamper) await state.tamper(envelope);
      return jsonResponse(envelope);
    }
    if (path === '/api/v1/browser/session/verify') {
      const message = challenges.get(body.challenge_id);
      assert.ok(await verify(message.public_key, body.signature, message));
      state.captures.push({public_key: message.public_key, signature: body.signature, message: clone(message)});
      const created = new Date().toISOString();
      currentSession = {schema: 'sab.browser_session.v1', subject_id: message.subject_id, public_key: message.public_key,
        display_name: identities.get(message.subject_id).display_name, created_at: created,
        expires_at: new Date(Date.parse(created) + 21600000).toISOString(), csrf_token: 'ef'.repeat(32), ...NONE};
      return jsonResponse(currentSession);
    }
    if (path === '/api/v1/browser/session') return jsonResponse({schema: 'sab.browser_session_observation.v1', session: currentSession, ...NONE});
    if (path === '/api/v1/browser/session/logout') {
      assert.deepEqual(body, {csrf_token: currentSession.csrf_token}); currentSession = null;
      return jsonResponse({schema: 'sab.browser_session_logout.v1', signed_out: true, ...NONE});
    }
    if (path === '/api/v1/agents/me/home') {
      const subject = new URL(url).searchParams.get('subject_id');
      if (!identities.has(subject)) return new Response('{}', {status: 404});
      return jsonResponse({schema: 'sab.agent_home.v1', subject_id: subject, identity: identities.get(subject),
        key_control: bindings.get(subject), ...NONE});
    }
    throw new Error(`Unexpected test path ${path}`);
  };
  return state;
}

test('Python compact ensure_ascii bytes, hashes and real Python signature interoperate', async () => {
  environment();
  for (const item of fixture.canonical_cases) {
    assert.equal(canonicalJSON(item.value), item.canonical);
    assert.equal(await hashCanonical(item.value), item.sha256);
    assert.equal(canonicalJSON(parseStrictJSON(item.canonical)), item.canonical);
  }
  assert.equal(canonicalJSON(fixture.envelope.message), fixture.canonical_message);
  assert.ok(await verify(fixture.registration.public_key, fixture.signature, fixture.envelope.message));
  assert.equal(await verify(fixture.registration.public_key, fixture.signature, {...fixture.envelope.message, action: 'revoke'}), false);
  const message = await validateKeyChallenge(fixture.envelope, {action: 'register', origin: ORIGIN,
    subject_id: fixture.envelope.message.subject_id, public_key: fixture.registration.public_key,
    registration: fixture.registration, now: Date.parse('2026-09-09T00:00:01Z')});
  assert.equal(canonicalJSON(message), fixture.canonical_message);
});

test('signed JSON rejects ambiguous values, duplicate decoded keys and non-JSON accessors', () => {
  for (const text of ['{"a":1,"\\u0061":2}', '{"__proto__":1,"__proto__":2}', '1.0', '1e0', '9007199254740992', '-0',
    'NaN', 'Infinity', '[01]', '{"a":1,}', '[1,]', '"\\ud800"', '"\\udc00"', '"\u0001"', 'true false', '[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]']) {
    assert.throws(() => parseStrictJSON(text), ParticipantError, text);
  }
  let invoked = false;
  const getter = {get value() { invoked = true; return 1; }};
  const arrayGetter = []; Object.defineProperty(arrayGetter, '0', {get() { invoked = true; return 1; }});
  const hidden = {}; Object.defineProperty(hidden, 'value', {value: 1});
  for (const value of [undefined, NaN, Infinity, -0, 1.5, 9007199254740992, 1n, '\ud800', '\udc00', new Date(), new Map(),
    getter, arrayGetter, hidden, new Array(1), {[Symbol('key')]: 1}]) assert.throws(() => canonicalJSON(value), ParticipantError);
  assert.equal(invoked, false);
  assert.equal(canonicalJSON(parseStrictJSON('{"__proto__":{"x":1}}')), '{"__proto__":{"x":1}}');
  assert.throws(() => canonicalJSON({x: 'a'.repeat(256 * 1024)}), /document too large/);
});

test('complete key-control intent rejects every remote substitution before signing', async () => {
  environment();
  const intent = {action: 'register', origin: ORIGIN, subject_id: fixture.envelope.message.subject_id,
    public_key: fixture.registration.public_key, registration: fixture.registration, now: Date.parse('2026-09-09T00:00:01Z')};
  const mutations = [
    (e) => { e.unknown = 'x'; }, (e) => { e.standing_effect = 'provisional'; }, (e) => { e.canonicalization = 'JCS'; },
    (e) => { e.message.action = 'rotate'; }, (e) => { e.message.audience = 'https://other.example'; },
    (e) => { e.message.path = '/api/v1/seeds'; }, (e) => { e.message.method = 'GET'; },
    (e) => { e.message.subject_id = 'agent_ed25519_' + '00'.repeat(16); }, (e) => { e.message.public_key = '00'.repeat(32); },
    (e) => { e.message.nonce = 'AA'.repeat(32); }, (e) => { e.message.challenge_id = 'sab_kc_challenge_wrong'; },
    (e) => { e.message.proposed_identity_sha256 = '00'.repeat(32); }, (e) => { e.message.unknown = null; },
    (e) => { e.message.expires_at = '2026-09-09T00:00:01Z'; },
    (e) => { e.message.expires_at = '2026-09-09T00:02:00.000002Z'; }, // 120s + 1 microsecond
    (e) => { e.message.issued_at = '2026-09-09T00:00:06.000001Z'; }, // skew + 1 microsecond
    (e) => { e.message.issued_at = '2026-02-30T00:00:00Z'; },
    async (e) => { e.message.proposed_identity.display_name = 'changed'; e.message.proposed_identity_sha256 = await hashCanonical(e.message.proposed_identity); },
    async (e) => { e.message.proposed_identity.operator_backing.operator_id = 'changed'; e.message.proposed_identity_sha256 = await hashCanonical(e.message.proposed_identity); },
    async (e) => { e.message.proposed_identity.external_attestations = [{verified: true}]; e.message.proposed_identity_sha256 = await hashCanonical(e.message.proposed_identity); },
    async (e) => { e.message.proposed_identity.evidence_refs = [1]; e.message.proposed_identity_sha256 = await hashCanonical(e.message.proposed_identity); },
  ];
  for (const mutation of mutations) { const bad = clone(fixture.envelope); await mutation(bad); await rejects(() => validateKeyChallenge(bad, intent)); }
  const revoked = clone(fixture.envelope); revoked.message.action = 'revoke';
  await rejects(() => validateKeyChallenge(revoked, {...intent, action: 'revoke', registration: null}), 'revocation_cannot_register_identity');
  revoked.message.proposed_identity = null; revoked.message.proposed_identity_sha256 = null;
  await validateKeyChallenge(revoked, {...intent, action: 'revoke', registration: null});
});

test('creation is quiet; real non-extractable keys survive storage roundtrip and reload', async () => {
  const env = environment();
  const client = await createParticipant({origin: ORIGIN});
  assert.deepEqual(await client.list(), []); assert.equal(env.calls.sign, 0); assert.equal(env.calls.generate, 0); assert.equal(env.calls.fetch.length, 0);
  const record = await client.createKey({display_name: ' \u0085試験 😀\u3000', operator_backing: {operator_id: ' synthetic ', operator_kind: 'human'}});
  assert.equal(record.registration.display_name, '試験 😀'); assert.equal(record.registration.operator_backing.operator_id, 'synthetic');
  assert.equal(record.id, await subjectFor(record.public_key)); assert.equal(record.status, 'retained'); assert.equal(record.identity, null);
  assert.deepEqual(Object.keys(record).sort(), ['id','subject_id','public_key','status','registration','identity','successor_id','predecessor_id'].sort());
  const storedKey = env.storage.snapshot().records[record.id].privateKey;
  assert.equal(storedKey.extractable, false); assert.equal(storedKey.algorithm.name, 'Ed25519');
  await assert.rejects(() => webcrypto.subtle.exportKey('pkcs8', storedKey));
  assert.equal(env.calls.sign, 1); assert.equal(env.calls.fetch.length, 0); client.close();
  const reloaded = await createParticipant({origin: ORIGIN});
  assert.equal((await reloaded.list())[0].id, record.id); assert.equal(env.calls.sign, 1);
  const server = fakeServer(env); await reloaded.enroll(record.id);
  assert.equal((await reloaded.list())[0].status, 'active'); assert.equal(server.captures.length, 1);
  reloaded.close();
});

test('storage failure prevents registration and never falls back to a server key', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN});
  env.storage.failWrites(true);
  await rejects(() => client.createKey({display_name: 'synthetic'}), 'key_storage_transaction_failed');
  assert.equal(env.calls.fetch.length, 0); assert.equal(env.calls.sign, 0); assert.equal(env.calls.generate, 0);
  env.storage.failWrites(false); assert.deepEqual(await client.list(), []); client.close();
  globalThis.indexedDB = undefined;
  await rejects(() => createParticipant({origin: ORIGIN}), 'indexeddb_unavailable_use_agora_key_control_cli');
});

test('a CryptoKey persistence failure after generation prevents even the local roundtrip signature', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN});
  env.storage.failWrites(2); // First write acquires lease; second attempts key storage.
  await rejects(() => client.createKey({display_name: 'Synthetic'}), 'key_storage_transaction_failed');
  assert.equal(env.calls.generate, 1); assert.equal(env.calls.sign, 0); assert.equal(env.calls.fetch.length, 0);
  assert.deepEqual(await client.list(), []); client.close();
});

test('enrollment tampering leaves the retained key pending and produces no remote proof', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN}), server = fakeServer(env);
  const record = await client.createKey({display_name: 'Synthetic'}), before = env.calls.sign;
  server.tamper = (e) => { e.message.audience = 'https://different.example'; };
  await rejects(() => client.enroll(record.id), 'challenge_does_not_match_intent');
  assert.equal(env.calls.sign, before); assert.equal(env.calls.fetch.length, 1); assert.equal(server.captures.length, 0);
  assert.equal((await client.list())[0].status, 'enrollment_pending');
  server.tamper = null; await client.enroll(record.id); assert.equal(env.calls.generate, 1);
  assert.equal((await client.list())[0].status, 'active'); client.close();
});

test('fresh session proof is separate from enrollment; GET and logout never sign', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN}), server = fakeServer(env);
  const record = await client.createKey({display_name: 'Synthetic'}); await client.enroll(record.id);
  const before = env.calls.sign; assert.equal((await client.session()).session, null); assert.equal(env.calls.sign, before);
  const session = await client.signIn(record.id); assert.equal(env.calls.sign, before + 1);
  assert.equal(server.captures[1].message.schema, 'sab.browser_session_message.v1');
  assert.equal((await client.session()).session.expires_at, session.expires_at);
  await client.signOut(session.csrf_token); assert.equal((await client.session()).session, null); assert.equal(env.calls.sign, before + 1);
  server.tamper = (e) => { e.message.path = '/api/v1/agents/verify'; };
  await rejects(() => client.signIn(record.id), 'session_challenge_does_not_match_intent');
  assert.equal(env.calls.sign, before + 1); client.close();
});

test('rotation connection loss retains both keys; reconciliation and retry do not replace them', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN}), server = fakeServer(env);
  const old = await client.createKey({display_name: 'Old'}); await client.enroll(old.id);
  server.fail = (path) => path === '/api/v1/agents/verify';
  await rejects(() => client.rotate(old.id, {display_name: 'New'}), 'transport_failed_check_local_custody_before_retry');
  const retained = await client.list(), predecessor = retained.find((r) => r.id === old.id), successor = retained.find((r) => r.id !== old.id);
  assert.equal(retained.length, 2); assert.equal(predecessor.status, 'rotation_pending'); assert.equal(successor.status, 'rotation_pending');
  assert.equal(predecessor.successor_id, successor.id); assert.equal(successor.predecessor_id, old.id);
  assert.equal((await client.reconcile(old.id)).status, 'rotation_pending');
  const generated = env.calls.generate;
  await rejects(() => client.rotate(old.id, {display_name: 'Different'}), 'pending_rotation_registration_must_remain_unchanged');
  assert.equal(env.calls.generate, generated); server.fail = null;
  const rotated = await client.rotate(old.id, {display_name: 'New'}); assert.equal(rotated.record.id, successor.id); assert.equal(env.calls.generate, generated);
  const after = await client.list(); assert.equal(after.find((r) => r.id === old.id).status, 'superseded'); assert.equal(after.find((r) => r.id === successor.id).status, 'active');
  assert.equal(Object.keys(env.storage.snapshot().records).length, 2);
  await rejects(() => client.signIn(old.id), 'active_retained_identity_required_reconcile_pending_operations');
  server.fail = (path) => path === '/api/v1/agents/verify';
  await rejects(() => client.revoke(successor.id)); assert.equal((await client.reconcile(successor.id)).status, 'revocation_pending');
  server.fail = null; await client.revoke(successor.id); assert.equal((await client.list()).find((r) => r.id === successor.id).status, 'revoked');
  assert.equal(Object.keys(env.storage.snapshot().records).length, 2); client.close();
});

test('lost response after committed rotation reconciles both retained keys without signing or replacement', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN}); fakeServer(env);
  const old = await client.createKey({display_name: 'Old'}); await client.enroll(old.id);
  const serve = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const result = await serve(url, options);
    if (new URL(url).pathname === '/api/v1/agents/verify') throw new Error('Receipt lost after durable acceptance');
    return result;
  };
  await rejects(() => client.rotate(old.id, {display_name: 'Successor'}));
  const pending = await client.list(), successor = pending.find((r) => r.id !== old.id);
  assert.equal(pending.length, 2); assert.equal(successor.status, 'rotation_pending');
  const before = env.calls.sign;
  assert.equal((await client.reconcile(old.id)).status, 'superseded');
  assert.equal((await client.reconcile(successor.id)).status, 'active');
  assert.equal(env.calls.generate, 2); assert.equal(env.calls.sign, before);
  assert.equal(Object.keys(env.storage.snapshot().records).length, 2);
  await rejects(() => client.rotate(old.id, {display_name: 'Replacement'}));
  assert.equal(env.calls.generate, 2); client.close();
});

test('atomic custody lease blocks overlapping mutations across tabs without Web Locks', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN}), other = await createParticipant({origin: ORIGIN}), server = fakeServer(env);
  const record = await client.createKey({display_name: 'Synthetic'});
  let enter, release; const entered = new Promise((resolve) => { enter = resolve; }); const gate = new Promise((resolve) => { release = resolve; });
  server.before = async (path) => { if (path === '/api/v1/agents/challenge') { enter(); await gate; } };
  const operation = client.enroll(record.id); await entered;
  await rejects(() => other.createKey({display_name: 'Overlapping'}), 'another_tab_operation_in_progress');
  assert.equal(env.calls.generate, 1); release(); await operation;
  assert.equal((await other.list())[0].status, 'active'); client.close(); other.close();
});

test('bounded transport denies duplicate JSON, redirects, unsafe origins and malformed UTF8; observations allow finite scores', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN});
  for (const origin of ['https://different.example', 'http://example.com', `${ORIGIN}/`, `${ORIGIN}/path`]) await rejects(() => createParticipant({origin}));
  for (const path of ['https://different.example/api/v1/seeds', '//different.example/api/v1/seeds', '/api/v1/../../secret', '/api/v1/x#y', '/api/v1/\\other']) await rejects(() => client.request(path));
  assert.equal(env.calls.fetch.length, 0);
  globalThis.fetch = async () => rawResponse('{"score":0.0,"rate":0.25,"exponent":1e-2}');
  const observation = await client.request('/api/v1/seeds'); assert.equal(observation.score, 0); assert.equal(observation.rate, 0.25);
  await rejects(() => client.request('/api/v1/seeds', {strictNumbers: true}), 'only_safe_integers_supported');
  for (const text of ['{"a":1,"\\u0061":2}', '{"a":1e999}', '{"a":9007199254740993}', '{"a":"\\ud800"}', '[]']) {
    globalThis.fetch = async () => rawResponse(text); await rejects(() => client.request('/api/v1/seeds'));
  }
  globalThis.fetch = async () => rawResponse(' '.repeat(256 * 1024 + 1)); await rejects(() => client.request('/api/v1/seeds'), 'response_too_large');
  globalThis.fetch = async () => rawResponse(new Uint8Array([0xff])); await rejects(() => client.request('/api/v1/seeds'));
  globalThis.fetch = async () => { const response = jsonResponse({}); Object.defineProperty(response, 'redirected', {value: true}); return response; };
  await rejects(() => client.request('/api/v1/seeds'), 'redirect_refused');
  globalThis.fetch = async (_url, options) => { assert.ok(options.body.length > 72000); assert.equal(options.headers['X-CSRF-Token'], 'test'); return jsonResponse({accepted: true}); };
  assert.equal((await client.request('/api/v1/seeds', {method: 'POST', body: {claim: 'あ'.repeat(12001)}, csrfToken: 'test'})).accepted, true);
  globalThis.location.origin = 'https://changed.example'; await rejects(() => client.request('/api/v1/seeds'), 'origin_changed');
  client.close();
});

test('fixed contribution signatures match Python builders, preserve reviewed actors and refuse unsafe input', async () => {
  const env = environment(), client = await createParticipant({origin: ORIGIN}), server = fakeServer(env);
  const record = await client.createKey({display_name: '署名 🧪'}); await client.enroll(record.id);
  const active = (await client.list())[0], captures = [];
  for (const sample of fixture.protocol) {
    const packet = clone(sample.packet);
    if (sample.action === 'seed') packet.claimant_identity = {subject_id: active.id, identity_ref: active.identity.identity_ref};
    if (sample.action === 'challenge') packet.challenger_identity = active.identity.identity_ref;
    const method = {seed: 'signSeed', challenge: 'signChallenge', witness: 'signWitness'}[sample.action];
    const signed = await client[method](record.id, packet), message = clone(sample.message);
    if (sample.action === 'seed') { message.seed_packet_sha256 = await hashCanonical(packet); message.claimant_identity = record.id; }
    if (sample.action === 'challenge') { message.challenge_packet_sha256 = await hashCanonical(packet); message.challenger_identity = active.identity.identity_ref; }
    const signature = sample.action === 'witness' ? signed.signature : signed.signature.signature;
    if (sample.action !== 'witness') assert.equal(canonicalJSON(signed.signature.signed_payload), canonicalJSON(message));
    assert.ok(await verify(record.public_key, signature, message));
    assert.equal(await verify(record.public_key, signature, {...message, created_at: '2026-09-09T01:00:00Z'}), false);
    captures.push({action: sample.action, packet, signed, public_key: record.public_key, signature, message});
  }
  const before = env.calls.sign;
  const badSeed = clone(fixture.protocol[0].packet); badSeed.claimant_identity = {subject_id: active.id, identity_ref: active.identity.identity_ref}; badSeed.claim = 0.5;
  await rejects(() => client.signSeed(record.id, badSeed), 'only_safe_integers_supported');
  badSeed.claim = 'Synthetic'; badSeed.claimant_identity = {...active.identity, display_name: 'Unreviewed identity'};
  await rejects(() => client.signSeed(record.id, badSeed), 'seed_does_not_match_signing_intent');
  const badChallenge = clone(fixture.protocol[1].packet); badChallenge.challenger_identity = fixture.envelope.message.subject_id;
  await rejects(() => client.signChallenge(record.id, badChallenge), 'challenge_does_not_match_signing_intent');
  await rejects(() => client.signWitness(record.id, {...fixture.protocol[2].packet, event_type: 'canon'}), 'witness_does_not_match_signing_intent');
  assert.equal(env.calls.sign, before); assert.equal(env.calls.fetch.length, 2);
  // Optional actual current Python client/router verification of Node signatures.
  if (process.env.SAB_TEST_PYTHON) {
    const result = spawnSync(process.env.SAB_TEST_PYTHON, ['-c', `
import json, sys
from datetime import datetime
from nacl.signing import VerifyKey
from agora.key_control_client import _challenge
from agora.sab_identity import canonical_json_bytes
from agora.sab_seeding_api import _hash_json, _seed_submit_message, _challenge_submit_message, _witness_event_message
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
data = json.load(sys.stdin)
for proof in data['keyControl']:
    m = proof['message']
    envelope = {'schema':'sab.key_control_challenge.v1','message':m,'signature_algorithm':'ed25519','canonicalization':'json-sort-keys-compact-v1','authority_effect':'none','standing_effect':'none'}
    assert _challenge(envelope, action=m['action'], origin=m['audience'], subject_id=m['subject_id'], public_key=m['public_key'], registration=data['registration'], observed_at=datetime.fromisoformat(m['issued_at'].replace('Z','+00:00'))) == m
    VerifyKey(bytes.fromhex(proof['public_key'])).verify(canonical_json_bytes(m), bytes.fromhex(proof['signature']))
for row in data['contributions']:
    p = row['packet']
    if row['action'] == 'seed':
        message = _seed_submit_message(seed_packet_hash=_hash_json(p), claimant_identity=p['claimant_identity']['subject_id'], authority_lease_id=p['authority_lease']['lease_ref'], created_at=p['created_at'])
    elif row['action'] == 'challenge':
        message = _challenge_submit_message(target_seed_id=p['target_seed_id'], target_claim_id=p['target_claim_id'], challenge_packet_hash=_hash_json(p), challenger_identity=p['challenger_identity'], created_at=p['created_at'])
    else:
        message = _witness_event_message(event_type=p['event_type'], subject_type=p['subject_type'], subject_id=p['subject_id'], payload_hash=_hash_json(p['payload']), prev_hash=p['prev_hash'], created_at=p['created_at'])
    assert message == row['message']
    VerifyKey(bytes.fromhex(row['public_key'])).verify(canonical_json_bytes(message), bytes.fromhex(row['signature']))
    if row['action'] in {'seed', 'challenge'}:
        schema = json.loads(Path('nodes/schemas/sab.' + row['action'] + '_packet.v1.schema.json').read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(row['signed'])
print('All current Python router messages and Ed25519 signatures verified')
`], {input: JSON.stringify({contributions: captures, keyControl: server.captures, registration: active.registration}), encoding: 'utf8', cwd: fileURLToPath(new URL('../../', import.meta.url)), env: {...process.env, PYTHONDONTWRITEBYTECODE: '1'}});
    assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /All current Python/);
  }
  client.close();
});

test('session observations refuse reversed or overlong lifetimes and extra bearer fields', async () => {
  environment(); const client = await createParticipant({origin: ORIGIN}), now = Date.now();
  const session = {schema: 'sab.browser_session.v1', subject_id: fixture.envelope.message.subject_id,
    public_key: fixture.registration.public_key, display_name: 'Synthetic', created_at: new Date(now).toISOString(),
    expires_at: new Date(now + 21600000).toISOString(), csrf_token: 'ab'.repeat(32), ...NONE};
  const observation = () => jsonResponse({schema: 'sab.browser_session_observation.v1', session, ...NONE});
  globalThis.fetch = async () => observation(); await client.session();
  session.expires_at = new Date(now + 21600001).toISOString(); await rejects(() => client.session(), 'invalid_browser_session');
  session.created_at = new Date(now + 4000).toISOString(); session.expires_at = new Date(now + 3000).toISOString();
  await rejects(() => client.session(), 'invalid_browser_session');
  session.created_at = new Date(now).toISOString(); session.expires_at = new Date(now + 21600000).toISOString(); session.bearer_token = 'never-in-json';
  await rejects(() => client.session(), 'unexpected_protocol_fields'); client.close();
});

test('session challenge rejects substituted nonce, identity, lifetime, effects and extra fields', () => {
  environment();
  const key = fixture.envelope.message.public_key, subject = fixture.envelope.message.subject_id;
  const envelope = {schema: 'sab.browser_session_challenge.v1', signature_algorithm: 'ed25519', canonicalization: CANON, ...NONE,
    message: {schema: 'sab.browser_session_message.v1', action: 'open_session', audience: ORIGIN, method: 'POST',
      path: '/api/v1/browser/session/verify', challenge_id: 'sab_browser_challenge_' + 'ab'.repeat(16), nonce: 'cd'.repeat(32),
      subject_id: subject, public_key: key, issued_at: '2026-09-09T00:00:00Z', expires_at: '2026-09-09T00:02:00Z'}};
  const intent = {origin: ORIGIN, subject_id: subject, public_key: key, now: Date.parse('2026-09-09T00:00:01Z')};
  assert.equal(validateSessionChallenge(envelope, intent).action, 'open_session');
  for (const [field, value] of [['nonce', 'not-random'], ['public_key', '00'.repeat(32)], ['subject_id','other'], ['expires_at','2026-09-09T00:02:00.000001Z'],
    ['action','register'], ['challenge_id','sab_session_challenge_' + 'ab'.repeat(16)], ['extra',true]]) {
    const bad = clone(envelope); bad.message[field] = value; assert.throws(() => validateSessionChallenge(bad, intent), ParticipantError);
  }
  assert.throws(() => validateSessionChallenge({...envelope, authority_effect: 'local_permission'}, intent), ParticipantError);
  assert.throws(() => validateSessionChallenge(envelope, {...intent, now: Date.parse(envelope.message.expires_at)}), ParticipantError);
});
