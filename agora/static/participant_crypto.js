/* Participant-held keys. This module never starts an operation when imported. */
const encoder = new TextEncoder();
const CANON = 'json-sort-keys-compact-v1';
const VERIFY = '/api/v1/agents/verify';
const SESSION_VERIFY = '/api/v1/browser/session/verify';
const KEY = /^[0-9a-f]{64}$/;
const SUBJECT = /^agent_ed25519_[0-9a-f]{32}$/;
const MAX_BYTES = 256 * 1024;
const EFFECTS = ['authority_effect', 'standing_effect'];
const pyStrip = (value) => value.replace(/^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g, '');

export class ParticipantError extends Error {
  constructor(code, status = null) {
    super(code.replaceAll('_', ' '));
    this.name = 'ParticipantError';
    this.code = code;
    this.status = status;
  }
}
const fail = (code) => { throw new ParticipantError(code); };
const plain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && [Object.prototype, null].includes(Object.getPrototypeOf(v));
function fields(value, required, optional = []) {
  if (!plain(value) || required.some((key) => !Object.hasOwn(value, key))
      || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) fail('unexpected_protocol_fields');
  return value;
}
function string(value, max = 2048, nonempty = true) {
  if (typeof value !== 'string' || Array.from(value).length > max || (nonempty && !pyStrip(value))) fail('invalid_public_text');
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail('unpaired_unicode_surrogate');
    } else if (c >= 0xdc00 && c <= 0xdfff) fail('unpaired_unicode_surrogate');
  }
  return value;
}
function pythonKeyOrder(a, b) {
  const left = Array.from(a, (c) => c.codePointAt(0));
  const right = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
}
function quote(value) {
  string(value, MAX_BYTES, false);
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
export function canonicalJSON(value) {
  let nodes = 0;
  function encode(v, depth) {
    if (++nodes > 12000 || depth > 24) fail('json_complexity_limit');
    if (v === null) return 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'string') return quote(v);
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v) || Object.is(v, -0)) fail('only_safe_integers_supported');
      return String(v);
    }
    if (Array.isArray(v)) {
      if (Reflect.ownKeys(v).length !== v.length + 1) fail('non_json_array');
      const items = [];
      for (let i = 0; i < v.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(v, String(i));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('non_json_array');
        items.push(encode(descriptor.value, depth + 1));
      }
      return `[${items.join(',')}]`;
    }
    if (!plain(v)) fail('plain_json_required');
    const descriptors = Object.getOwnPropertyDescriptors(v);
    const keys = Reflect.ownKeys(v);
    if (keys.some((key) => typeof key !== 'string' || !descriptors[key].enumerable || !Object.hasOwn(descriptors[key], 'value'))) fail('plain_json_required');
    return `{${keys.sort(pythonKeyOrder).map((key) => `${quote(key)}:${encode(descriptors[key].value, depth + 1)}`).join(',')}}`;
  }
  const result = encode(value, 0);
  if (encoder.encode(result).length > MAX_BYTES) fail('document_too_large');
  return result;
}
function parseJSON(text, allowFloats) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_BYTES) fail('document_too_large');
  let cursor = 0, nodes = 0;
  const space = () => { while (/^[\x20\t\r\n]$/.test(text[cursor] ?? '')) cursor++; };
  function quoted() {
    const start = cursor++;
    while (cursor < text.length) {
      const c = text[cursor++];
      if (c === '"') {
        let result;
        try { result = JSON.parse(text.slice(start, cursor)); } catch { fail('invalid_json'); }
        return string(result, MAX_BYTES, false);
      }
      if (c === '\\') cursor++;
    }
    fail('invalid_json');
  }
  function value(depth) {
    if (++nodes > 12000 || depth > 24) fail('json_complexity_limit');
    space();
    const c = text[cursor];
    if (c === '"') return quoted();
    if (c === '{') {
      cursor++; space();
      const result = Object.create(null);
      if (text[cursor] === '}') { cursor++; return result; }
      while (true) {
        space();
        if (text[cursor] !== '"') fail('invalid_json');
        const key = quoted();
        if (Object.hasOwn(result, key)) fail('duplicate_json_member');
        space(); if (text[cursor++] !== ':') fail('invalid_json');
        result[key] = value(depth + 1);
        space(); const separator = text[cursor++];
        if (separator === '}') return result;
        if (separator !== ',') fail('invalid_json');
      }
    }
    if (c === '[') {
      cursor++; space(); const result = [];
      if (text[cursor] === ']') { cursor++; return result; }
      while (true) {
        result.push(value(depth + 1)); space(); const separator = text[cursor++];
        if (separator === ']') return result;
        if (separator !== ',') fail('invalid_json');
      }
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, cursor)) { cursor += token.length; return result; }
    }
    const pattern = allowFloats ? /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/ : /^-?(?:0|[1-9][0-9]*)/;
    const match = pattern.exec(text.slice(cursor));
    if (!match) fail('invalid_json');
    cursor += match[0].length;
    if (/[.eE]/.test(text[cursor] ?? '')) fail('only_safe_integers_supported');
    const result = Number(match[0]);
    if (!Number.isFinite(result) || (Number.isInteger(result) && !Number.isSafeInteger(result))
        || (!allowFloats && (!Number.isSafeInteger(result) || Object.is(result, -0)))) fail('only_safe_integers_supported');
    return result;
  }
  const result = value(0); space();
  if (cursor !== text.length) fail('invalid_json');
  return result;
}
// Observations can contain finite scores. Signed documents use this stricter
// parser and canonicalJSON; their supported numeric language is safe integers.
export function parseStrictJSON(text) { return parseJSON(text, false); }
const copy = (v) => parseStrictJSON(canonicalJSON(v));
const equal = (a, b) => canonicalJSON(a) === canonicalJSON(b);
const hex = (bytes) => Array.from(new Uint8Array(bytes), (c) => c.toString(16).padStart(2, '0')).join('');
const unhex = (value) => Uint8Array.from(value.match(/../g), (part) => Number.parseInt(part, 16));
export async function hashCanonical(value) { return hex(await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(canonicalJSON(value)))); }
async function subjectFor(publicKey) { return `agent_ed25519_${hex(await crypto.subtle.digest('SHA-256', encoder.encode(publicKey))).slice(0, 32)}`; }
function originValue(value) {
  string(value, 300);
  let url;
  try { url = new URL(value); } catch { fail('invalid_configured_origin'); }
  if (value !== url.origin || url.username || url.password || url.search || url.hash
      || !['https:', 'http:'].includes(url.protocol)) fail('invalid_configured_origin');
  if (url.protocol === 'http:' && !(url.hostname === 'localhost' || url.hostname === '[::1]'
      || /^127\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}$/.test(url.hostname))) fail('https_or_loopback_required');
  return value;
}
function utc(value) {
  if (typeof value !== 'string' || value.startsWith('0000-') || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) fail('invalid_utc_time');
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) fail('invalid_utc_time');
  // Date.parse silently repairs invalid calendar dates. Check the whole second.
  if (new Date(millis).toISOString().slice(0, 19) !== value.slice(0, 19)) fail('invalid_utc_time');
  return millis;
}
function micros(value) {
  utc(value);
  const whole = Date.parse(`${value.slice(0, 19)}Z`);
  const fraction = /\.(\d{1,6})/.exec(value)?.[1] ?? '';
  return BigInt(whole) * 1000n + BigInt(fraction.padEnd(6, '0'));
}
function freshness(message, now) {
  const issued = micros(message.issued_at), expiry = micros(message.expires_at), observed = BigInt(Math.trunc(now)) * 1000n;
  if (!(expiry > issued && expiry - issued <= 120000000n && issued <= observed + 5000000n && observed < expiry)) fail('challenge_not_fresh');
}
function noneEffects(value) { if (EFFECTS.some((key) => value[key] !== 'none')) fail('unexpected_authority_effect'); }
async function registrationFor(input, publicKey) {
  fields(input, ['display_name'], ['controller', 'operator_backing']);
  const backing = input.operator_backing ?? {};
  fields(backing, [], ['operator_id', 'operator_kind', 'disclosure', 'backing_count_attestation']);
  const normalized = {
    display_name: pyStrip(string(input.display_name, 120)), public_key: publicKey,
    controller: input.controller ?? 'unknown',
    operator_backing: {
      operator_id: pyStrip(string(backing.operator_id ?? 'unknown', 160)),
      operator_kind: backing.operator_kind ?? 'unknown',
      disclosure: string(backing.disclosure ?? '', 1000, false),
      backing_count_attestation: backing.backing_count_attestation ?? 'unchecked',
    },
  };
  if (!['self', 'operator', 'org', 'unknown'].includes(normalized.controller)
      || !['human', 'organization', 'agent', 'unknown'].includes(normalized.operator_backing.operator_kind)
      || !['unchecked', 'self_attested'].includes(normalized.operator_backing.backing_count_attestation)) fail('invalid_public_registration');
  canonicalJSON(normalized);
  return normalized;
}
async function intendedIdentity(identity, registration, issuedAt) {
  fields(identity, ['schema', 'subject_id', 'identity_ref', 'display_name', 'identity_rail', 'public_key', 'controller',
    'operator_backing', 'external_attestations', 'created_at', 'revocation_status', 'evidence_refs']);
  const subject = await subjectFor(registration.public_key);
  const expected = {
    schema: 'sab.agent_identity.v1', subject_id: subject, identity_ref: `sab_identity_${subject}`,
    display_name: registration.display_name, identity_rail: 'ed25519', public_key: registration.public_key,
    controller: registration.controller, operator_backing: registration.operator_backing,
    external_attestations: [], revocation_status: 'active',
  };
  for (const key of Object.keys(expected)) if (!equal(identity[key], expected[key])) fail('challenge_changes_registration');
  if (micros(identity.created_at) > micros(issuedAt)) fail('identity_created_after_challenge');
  if (!Array.isArray(identity.evidence_refs) || identity.evidence_refs.length > 32) fail('invalid_identity_evidence');
  identity.evidence_refs.forEach((ref) => string(ref, 512));
}
export async function validateKeyChallenge(envelope, intent) {
  canonicalJSON(envelope);
  fields(envelope, ['schema', 'message', 'signature_algorithm', 'canonicalization', ...EFFECTS]);
  if (envelope.schema !== 'sab.key_control_challenge.v1' || envelope.signature_algorithm !== 'ed25519' || envelope.canonicalization !== CANON) fail('unsupported_challenge_contract');
  noneEffects(envelope);
  const message = fields(envelope.message, ['schema', 'action', 'audience', 'method', 'path', 'challenge_id', 'nonce',
    'subject_id', 'public_key', 'issued_at', 'expires_at', 'proposed_identity', 'proposed_identity_sha256']);
  const expected = {schema: 'sab.key_control_message.v1', action: intent.action, audience: intent.origin,
    method: 'POST', path: VERIFY, subject_id: intent.subject_id, public_key: intent.public_key};
  for (const key of Object.keys(expected)) if (message[key] !== expected[key]) fail('challenge_does_not_match_intent');
  if (!['register', 'rotate', 'revoke'].includes(intent.action) || !KEY.test(message.public_key)
      || !/^sab_kc_challenge_[0-9a-f]{32}$/.test(message.challenge_id) || !KEY.test(message.nonce)) fail('invalid_challenge_identifier');
  freshness(message, intent.now ?? Date.now());
  if (intent.action === 'revoke') {
    if (message.proposed_identity !== null || message.proposed_identity_sha256 !== null) fail('revocation_cannot_register_identity');
  } else {
    await intendedIdentity(message.proposed_identity, intent.registration, message.issued_at);
    if (message.proposed_identity_sha256 !== await hashCanonical(message.proposed_identity)) fail('identity_digest_mismatch');
  }
  return copy(message);
}
export function validateSessionChallenge(envelope, intent) {
  canonicalJSON(envelope);
  fields(envelope, ['schema', 'message', 'signature_algorithm', 'canonicalization', ...EFFECTS]);
  if (envelope.schema !== 'sab.browser_session_challenge.v1' || envelope.signature_algorithm !== 'ed25519' || envelope.canonicalization !== CANON) fail('unsupported_session_contract');
  noneEffects(envelope);
  const message = fields(envelope.message, ['schema', 'action', 'audience', 'method', 'path', 'challenge_id', 'nonce',
    'subject_id', 'public_key', 'issued_at', 'expires_at']);
  const expected = {schema: 'sab.browser_session_message.v1', action: 'open_session', audience: intent.origin,
    method: 'POST', path: SESSION_VERIFY, subject_id: intent.subject_id, public_key: intent.public_key};
  for (const key of Object.keys(expected)) if (message[key] !== expected[key]) fail('session_challenge_does_not_match_intent');
  if (!/^sab_browser_challenge_[0-9a-f]{32}$/.test(message.challenge_id) || !KEY.test(message.nonce) || !KEY.test(message.public_key)) fail('invalid_session_identifier');
  freshness(message, intent.now ?? Date.now());
  return copy(message);
}
function bindingCheck(binding, expected) {
  fields(binding, ['schema', 'subject_id', 'public_key', 'status', 'proof_id', 'proved_at', 'successor_subject_id', 'scope', ...EFFECTS]);
  if (!equal(binding, {schema: 'sab.key_control_binding.v1', scope: 'key_control_only', authority_effect: 'none', standing_effect: 'none', ...expected})) fail('unexpected_key_control_binding');
}
async function receiptCheck(result, message, registration) {
  fields(result, ['schema', 'action', 'challenge_id', 'proof_id', 'verified_at', 'identity', 'binding', 'previous_binding', ...EFFECTS]);
  noneEffects(result);
  if (result.schema !== 'sab.key_control_result.v1' || result.action !== message.action || result.challenge_id !== message.challenge_id
      || !/^sab_kc_proof_[0-9a-f]{32}$/.test(result.proof_id) || micros(result.verified_at) < micros(message.issued_at)
      || micros(result.verified_at) >= micros(message.expires_at)) fail('unexpected_key_control_receipt');
  if (message.action === 'revoke') {
    await intendedIdentity({...result.identity, revocation_status: 'active'}, registration, result.verified_at);
    if (result.identity.revocation_status !== 'revoked') fail('unexpected_revocation_receipt');
  } else if (!equal(result.identity, message.proposed_identity)) fail('receipt_changes_signed_identity');
  const status = message.action === 'revoke' ? 'revoked' : 'active';
  bindingCheck(result.binding, {subject_id: result.identity.subject_id, public_key: result.identity.public_key, status,
    proof_id: result.proof_id, proved_at: result.verified_at, successor_subject_id: null});
  if (message.action === 'rotate') bindingCheck(result.previous_binding, {subject_id: message.subject_id, public_key: message.public_key,
    status: 'superseded', proof_id: result.proof_id, proved_at: result.verified_at, successor_subject_id: result.identity.subject_id});
  else if (result.previous_binding !== null) fail('unexpected_previous_binding');
  return result;
}
function sessionCheck(session, record = null) {
  fields(session, ['schema', 'subject_id', 'public_key', 'display_name', 'created_at', 'expires_at', 'csrf_token', ...EFFECTS]);
  noneEffects(session);
  const created = micros(session.created_at), expiry = micros(session.expires_at), now = BigInt(Date.now()) * 1000n;
  if (session.schema !== 'sab.browser_session.v1' || !SUBJECT.test(session.subject_id) || !KEY.test(session.public_key)
      || typeof session.csrf_token !== 'string' || !/^[0-9a-f]{64}$/.test(session.csrf_token)
      || expiry <= now || expiry <= created || expiry - created > 21600000000n
      || created > now + 5000000n) fail('invalid_browser_session');
  if (record && (session.subject_id !== record.subject_id || session.public_key !== record.public_key
      || session.display_name !== record.registration.display_name)) fail('session_changes_identity');
  string(session.display_name, 120);
  return session;
}
function publicRecord(record) {
  if (!record) return null;
  return copy({id: record.id, subject_id: record.subject_id, public_key: record.public_key, status: record.status,
    registration: record.registration, identity: record.identity, successor_id: record.successor_id, predecessor_id: record.predecessor_id});
}
async function openVault(origin) {
  if (!globalThis.indexedDB) fail('indexeddb_unavailable_use_agora_key_control_cli');
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open('sab-participant-custody-v1', 1);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains('custody')) request.result.createObjectStore('custody'); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new ParticipantError('indexeddb_unavailable_use_agora_key_control_cli'));
    request.onblocked = () => reject(new ParticipantError('close_other_tabs_to_open_key_storage'));
  });
  db.onversionchange = () => db.close();
  function update(change, write = true) {
    return new Promise((resolve, reject) => {
      let tx, store, request;
      try {
        tx = db.transaction('custody', write ? 'readwrite' : 'readonly');
        store = tx.objectStore('custody'); request = store.get('vault');
      } catch { reject(new ParticipantError('key_storage_transaction_failed')); return; }
      let result;
      request.onsuccess = () => {
        try {
          const vault = request.result ?? {schema: 'sab.browser_custody.v1', origin, records: {}, lease: null};
          if (vault.schema !== 'sab.browser_custody.v1' || vault.origin !== origin || !plain(vault.records)) fail('custody_origin_mismatch');
          result = change(vault);
          if (write) store.put(vault, 'vault');
        } catch (error) { tx.abort(); reject(error instanceof ParticipantError ? error : new ParticipantError('key_storage_transaction_failed')); }
      };
      tx.oncomplete = () => resolve(result);
      tx.onabort = tx.onerror = () => reject(new ParticipantError('key_storage_transaction_failed'));
    });
  }
  return {update, read: (change) => update(change, false), close: () => db.close()};
}

export async function createParticipant({origin}) {
  origin = originValue(origin);
  if (origin !== globalThis.location?.origin) fail('configured_origin_must_match_this_page');
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) fail('secure_webcrypto_required_use_agora_key_control_cli');
  const vault = await openVault(origin);
  function checkOrigin() { if (globalThis.location?.origin !== origin) fail('origin_changed'); }
  async function request(path, {method = 'GET', body, csrfToken, strictNumbers = false} = {}) {
    checkOrigin();
    if (typeof path !== 'string' || !path.startsWith('/api/v1/') || path.includes('\\') || path.includes('#')) fail('invalid_local_api_path');
    const target = new URL(path, origin);
    if (target.origin !== origin || !target.pathname.startsWith('/api/v1/') || !['GET', 'POST'].includes(method) || (method === 'GET' && body !== undefined)) fail('invalid_local_api_request');
    const raw = body === undefined ? undefined : canonicalJSON(body);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const headers = {Accept: 'application/json'};
      if (raw !== undefined) headers['Content-Type'] = 'application/json';
      if (csrfToken !== undefined) headers['X-CSRF-Token'] = string(csrfToken, 128);
      const response = await fetch(target.href, {method, body: raw, headers, credentials: 'same-origin',
        mode: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'same-origin', signal: controller.signal});
      if (response.redirected || (response.url && new URL(response.url).origin !== origin)) fail('redirect_refused');
      if (!response.ok) throw new ParticipantError('service_rejected_operation', response.status);
      if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') fail('json_response_required');
      const reader = response.body?.getReader();
      if (!reader) fail('bounded_response_stream_required');
      const chunks = []; let size = 0;
      try {
        while (true) {
          const {value, done} = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_BYTES) { controller.abort(); fail('response_too_large'); }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      const buffer = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
      const result = parseJSON(new TextDecoder('utf-8', {fatal: true}).decode(buffer), !strictNumbers);
      if (!plain(result)) fail('json_object_required');
      return result;
    } catch (error) {
      if (error instanceof ParticipantError) throw error;
      throw new ParticipantError('transport_failed_check_local_custody_before_retry');
    } finally { clearTimeout(timer); }
  }
  const protocolRequest = (path, options = {}) => request(path, {...options, strictNumbers: true});
  async function exclusive(operation) {
    checkOrigin();
    const run = async () => {
      const owner = hex(crypto.getRandomValues(new Uint8Array(16)));
      await vault.update((v) => {
        if (v.lease && v.lease.expires_at > Date.now()) fail('another_tab_operation_in_progress');
        v.lease = {owner, expires_at: Date.now() + 120000};
      });
      const write = (change) => vault.update((v) => {
        if (v.lease?.owner !== owner || v.lease.expires_at <= Date.now()) fail('custody_operation_lease_lost');
        return change(v);
      });
      try { return await operation(write); }
      finally { await vault.update((v) => { if (v.lease?.owner === owner) v.lease = null; }); }
    };
    return globalThis.navigator?.locks ? navigator.locks.request(`sab-participant:${origin}`, run) : run();
  }
  const get = (id) => vault.read((v) => {
    const record = v.records[id];
    if (!record || record.id !== id || record.subject_id !== id || !KEY.test(record.public_key)
        || record.privateKey?.type !== 'private' || record.privateKey.extractable !== false
        || record.privateKey.algorithm?.name !== 'Ed25519' || !record.privateKey.usages.includes('sign')) fail('retained_key_unavailable_use_agora_key_control_cli');
    return record;
  });
  async function sign(record, payload) {
    checkOrigin();
    return hex(await crypto.subtle.sign('Ed25519', record.privateKey, encoder.encode(canonicalJSON(payload))));
  }
  async function retain(input, write, predecessor = null) {
    let pair;
    try { pair = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']); }
    catch { fail('ed25519_unavailable_use_agora_key_control_cli'); }
    if (pair.privateKey.extractable) fail('private_key_must_be_nonextractable');
    const publicKey = hex(await crypto.subtle.exportKey('raw', pair.publicKey));
    const id = await subjectFor(publicKey);
    const registration = await registrationFor(copy(input), publicKey);
    const record = {id, subject_id: id, public_key: publicKey, privateKey: pair.privateKey, registration,
      identity: null, status: 'retained', successor_id: null, predecessor_id: predecessor};
    await write((v) => { if (Object.keys(v.records).length >= 32) fail('retained_key_limit'); v.records[id] = record; });
    const stored = await get(id);
    const proof = {kind: 'sab_local_custody_roundtrip', origin, nonce: hex(crypto.getRandomValues(new Uint8Array(32)))};
    const signature = await sign(stored, proof);
    if (!await crypto.subtle.verify('Ed25519', pair.publicKey, unhex(signature), encoder.encode(canonicalJSON(proof)))) fail('key_storage_roundtrip_failed');
    return stored;
  }
  async function operate(action, oldRecord, newRecord, write) {
    const registration = newRecord?.registration ?? (action === 'register' ? oldRecord.registration : null);
    const payload = {action};
    if (action !== 'register') payload.subject_id = oldRecord.subject_id;
    if (registration) payload.registration = registration;
    const pending = action === 'register' ? 'enrollment_pending' : action === 'rotate' ? 'rotation_pending' : 'revocation_pending';
    await write((v) => {
      v.records[oldRecord.id].status = pending;
      if (newRecord) { v.records[oldRecord.id].successor_id = newRecord.id; v.records[newRecord.id].status = 'rotation_pending'; }
    });
    const envelope = await protocolRequest('/api/v1/agents/challenge', {method: 'POST', body: payload});
    const message = await validateKeyChallenge(envelope, {action, origin, subject_id: oldRecord.subject_id,
      public_key: oldRecord.public_key, registration});
    const proof = {challenge_id: message.challenge_id, signature: await sign(oldRecord, message)};
    if (newRecord) proof.successor_signature = await sign(newRecord, message);
    const result = await receiptCheck(await protocolRequest(VERIFY, {method: 'POST', body: proof}), message, oldRecord.registration);
    await write((v) => {
      const target = v.records[newRecord?.id ?? oldRecord.id];
      target.status = action === 'revoke' ? 'revoked' : 'active'; target.identity = result.identity;
      if (newRecord) v.records[oldRecord.id].status = 'superseded';
    });
    return result;
  }
  async function active(id) {
    const record = await get(id);
    if (record.status !== 'active') fail('active_retained_identity_required_reconcile_pending_operations');
    return record;
  }
  function packetBase(packet) {
    const result = copy(packet);
    if (Object.hasOwn(result, 'signature')) fail('construct_a_new_unsigned_packet');
    return result;
  }
  function referenceCheck(reference) {
    fields(reference, ['lease_ref'], ['scope', 'expires_at', 'revoker', 'challenge_path']);
    if (!/^sab_lease_[A-Za-z0-9_.:-]{3,128}$/.test(reference.lease_ref)) fail('issued_lease_reference_required');
    if (reference.expires_at && utc(reference.expires_at) <= Date.now()) fail('lease_expired');
  }
  async function signedPacket(record, packet, message) {
    return {...packet, signature: {alg: 'ed25519', signer: record.subject_id,
      signature: await sign(record, message), canonicalization: CANON, signed_payload: message}};
  }
  return Object.freeze({
    request,
    list: () => vault.read((v) => Object.values(v.records).map(publicRecord)),
    createKey: (registration) => exclusive(async (write) => publicRecord(await retain(registration, write))),
    enroll: (id) => exclusive(async (write) => {
      const record = await get(id);
      if (!['retained', 'enrollment_pending'].includes(record.status)) fail('retained_identity_required_reconcile_pending_operations');
      return operate('register', record, null, write);
    }),
    signIn: (id) => exclusive(async () => {
      const record = await active(id);
      const challenge = await protocolRequest('/api/v1/browser/session/challenge', {method: 'POST', body: {subject_id: id}});
      const message = validateSessionChallenge(challenge, {origin, subject_id: id, public_key: record.public_key});
      return sessionCheck(await protocolRequest(SESSION_VERIFY, {method: 'POST', body: {
        challenge_id: message.challenge_id, signature: await sign(record, message),
      }}), record);
    }),
    session: async () => {
      const result = await protocolRequest('/api/v1/browser/session');
      fields(result, ['schema', 'session', ...EFFECTS]); noneEffects(result);
      if (result.schema !== 'sab.browser_session_observation.v1') fail('invalid_session_observation');
      if (result.session !== null) sessionCheck(result.session);
      return result;
    },
    signOut: async (csrfToken) => {
      const result = await protocolRequest('/api/v1/browser/session/logout', {method: 'POST', body: {csrf_token: csrfToken}});
      fields(result, ['schema', 'signed_out', ...EFFECTS]); noneEffects(result);
      if (result.schema !== 'sab.browser_session_logout.v1' || result.signed_out !== true) fail('unexpected_logout_result');
      return result;
    },
    rotate: (id, registration) => exclusive(async (write) => {
      const record = await get(id);
      if (!['active', 'rotation_pending'].includes(record.status)) fail('active_retained_identity_required_reconcile_pending_operations');
      const successor = record.status === 'rotation_pending' ? await get(record.successor_id) : await retain(registration, write, id);
      if (!equal(await registrationFor(copy(registration), successor.public_key), successor.registration)) fail('pending_rotation_registration_must_remain_unchanged');
      const receipt = await operate('rotate', record, successor, write);
      return {record: publicRecord(await get(successor.id)), receipt};
    }),
    revoke: (id) => exclusive(async (write) => {
      const record = await get(id);
      if (!['active', 'revocation_pending'].includes(record.status)) fail('active_retained_identity_required_reconcile_pending_operations');
      return operate('revoke', record, null, write);
    }),
    reconcile: (id) => exclusive(async (write) => {
      const record = await get(id);
      let home;
      try { home = await request(`/api/v1/agents/me/home?subject_id=${encodeURIComponent(id)}`); }
      catch (error) {
        if (error.status === 404 && record.status === 'enrollment_pending') {
          await write((v) => { v.records[id].status = 'retained'; });
          return publicRecord(await get(id));
        }
        throw error;
      }
      if (home.schema !== 'sab.agent_home.v1' || home.subject_id !== id) fail('cannot_reconcile_key_control');
      noneEffects(home);
      const binding = home.key_control;
      if (!plain(binding) || !['active', 'revoked', 'superseded'].includes(binding.status)
          || !/^sab_kc_proof_[0-9a-f]{32}$/.test(binding.proof_id)) fail('cannot_reconcile_key_control');
      const expectedIdentity = {...home.identity, revocation_status: 'active'};
      await intendedIdentity(expectedIdentity, record.registration, new Date().toISOString());
      bindingCheck(binding, {subject_id: id, public_key: record.public_key, status: binding.status,
        proof_id: binding.proof_id, proved_at: binding.proved_at, successor_subject_id: binding.successor_subject_id});
      utc(binding.proved_at);
      if (home.identity.revocation_status !== binding.status || (binding.status === 'superseded'
          ? binding.successor_subject_id !== record.successor_id : binding.successor_subject_id !== null)) fail('cannot_reconcile_key_control');
      await write((v) => {
        const unresolved = binding.status === 'active' && (
          record.status === 'revocation_pending' || (record.status === 'rotation_pending' && record.successor_id !== null));
        if (!unresolved) v.records[id].status = binding.status;
        v.records[id].identity = home.identity;
        // An active predecessor never proves that an ambiguous successor is safe to use.
      });
      return publicRecord(await get(id));
    }),
    signSeed: (id, input) => exclusive(async () => {
      const record = await active(id), packet = packetBase(input);
      if (packet.schema !== 'sab.seed_packet.v1' || !/^sab_seed_[A-Za-z0-9_.:-]{3,128}$/.test(packet.seed_id)
          || !equal(packet.claimant_identity, {subject_id: id, identity_ref: record.identity?.identity_ref})) fail('seed_does_not_match_signing_intent');
      referenceCheck(packet.authority_lease); utc(packet.created_at);
      return signedPacket(record, packet, {kind: 'sab_seed_submit', seed_packet_sha256: await hashCanonical(packet),
        claimant_identity: id, authority_lease_id: packet.authority_lease.lease_ref, created_at: packet.created_at});
    }),
    signChallenge: (id, input) => exclusive(async () => {
      const record = await active(id), packet = packetBase(input);
      if (packet.schema !== 'sab.challenge_packet.v1' || ![id, record.identity?.identity_ref].includes(packet.challenger_identity)
          || !/^sab_seed_[A-Za-z0-9_.:-]{3,128}$/.test(packet.target_seed_id)
          || !/^sab_claim_[A-Za-z0-9_.:-]{3,}$/.test(packet.target_claim_id)
          || !/^sab_challenge_[A-Za-z0-9_.:-]{3,}$/.test(packet.challenge_id)) fail('challenge_does_not_match_signing_intent');
      referenceCheck(packet.authority_lease); utc(packet.created_at);
      return signedPacket(record, packet, {kind: 'sab_challenge_submit', target_seed_id: packet.target_seed_id,
        target_claim_id: packet.target_claim_id, challenge_packet_sha256: await hashCanonical(packet),
        challenger_identity: packet.challenger_identity, created_at: packet.created_at});
    }),
    signWitness: (id, input) => exclusive(async () => {
      const record = await active(id), command = copy(input);
      fields(command, ['event_type', 'subject_type', 'subject_id', 'payload', 'prev_hash', 'created_at']);
      if (!['affirm', 'refuse'].includes(command.event_type) || command.subject_type !== 'seed'
          || !/^sab_seed_[A-Za-z0-9_.:-]{3,128}$/.test(command.subject_id) || !plain(command.payload)
          || !(command.prev_hash === 'genesis' || KEY.test(command.prev_hash))) fail('witness_does_not_match_signing_intent');
      utc(command.created_at);
      const message = {kind: 'sab_witness_event', event_type: command.event_type, subject_type: 'seed',
        subject_id: command.subject_id, payload_hash: await hashCanonical(command.payload),
        prev_hash: command.prev_hash, created_at: command.created_at};
      return {...command, actor_identity: id, signature: await sign(record, message)};
    }),
    close: () => vault.close(),
  });
}
