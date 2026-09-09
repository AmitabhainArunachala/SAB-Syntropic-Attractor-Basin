/* Explicit user actions over the fixed custody protocol. No load-time signatures. */
import {createParticipant, canonicalJSON} from './participant_crypto.js';

const root = document.querySelector('[data-participant-page]');
const byId = id => document.getElementById(id);
let client, records = [], selectedId = null, session = null, home = null, draft = null, busy = false;
const encode = encodeURIComponent;
const current = () => records.find(record => record.id === selectedId);
const message = (text, error = false) => {
  const node = byId('participant-status');
  node.textContent = text; node.dataset.error = String(error);
};
const explain = error => {
  if (error.code === 'session_cookie_unavailable') return 'The signed proof was accepted, but this browser did not retain its session cookie. Allow cookies for this instance, then sign in again.';
  if (error.status === 428 || error.status === 403) return 'Permission was refused. Check the selected key, operator requirements and current grant, then review again.';
  if (error.status === 409) return 'The record changed or this command was already received. Check the recorded status before reviewing a new action.';
  if (error.status === 410) return 'The proof or permission has expired. Refresh the recorded status, then try again.';
  if (error.status === 429 || error.status === 503) return 'This instance cannot admit another operation now. Your retained key is unchanged. Try later.';
  if (/unsupported|webcrypto|indexed|secure|storage/i.test(error.code || error.message)) return 'This browser cannot retain a supported signing key here. Use a secure supported browser or the installed key-control CLI.';
  return 'The operation could not be confirmed. Check recorded key or claim status before retrying; a lost response may follow an accepted command.';
};
function field(form, name) { return String(new FormData(form).get(name) || '').trim(); }
function reference(grant) {
  const lease = grant.lease;
  return {lease_ref:lease.lease_id, scope:lease.scope, expires_at:lease.expires_at,
    revoker:lease.revoker_id, challenge_path:lease.challenge_path};
}
function grants(action, target = null) {
  return (home?.active_authority_leases || []).filter(grant => grant.status === 'active'
    && grant.lease.subject_id === session?.subject_id && grant.lease.subject_public_key === current()?.public_key
    && grant.lease.allowed_actions.includes(action) && !grant.lease.forbidden_actions.includes(action)
    && (!target || grant.lease.target_seed_id === target));
}
function chooseGrants(id, items) {
  const select = byId(id), previous = select.value;
  select.replaceChildren(...items.map(grant => new Option(`${grant.lease.scope} · ${grant.lease.target_seed_id}`, grant.lease_id)));
  if (items.some(grant => grant.lease_id === previous)) select.value = previous;
}
async function run(label, operation) {
  if (busy) return;
  busy = true; root.setAttribute('aria-busy', 'true');
  const controls = [...root.querySelectorAll('button')].map(node => [node, node.disabled]);
  controls.forEach(([node]) => { node.disabled = true; });
  message(label);
  let resultMessage;
  try { resultMessage = await operation(); }
  catch (error) { resultMessage = [explain(error), true]; }
  finally {
    busy = false; root.removeAttribute('aria-busy');
    controls.forEach(([node, disabled]) => { node.disabled = disabled; });
    try { await refresh(); } catch (error) { clearCurrentPermission(); message(explain(error), true); resultMessage = null; }
    if (resultMessage) message(...(Array.isArray(resultMessage) ? resultMessage : [resultMessage]));
  }
}
function clearCurrentPermission() {
  session = null; home = null; draft = null;
  if (root.dataset.participantPage === 'key') return;
  for (const id of ['claim-fields','challenge-fields','witness-fields']) if (byId(id)) byId(id).disabled = true;
  for (const id of ['claim-sign','contribution-sign']) if (byId(id)) byId(id).disabled = true;
  for (const id of ['claim-grant','challenge-grant']) byId(id)?.replaceChildren();
  for (const id of ['claim-review','contribution-review']) if (byId(id)) byId(id).hidden = true;
  for (const id of ['claim-form','challenge-form','witness-form']) if (byId(id)) byId(id).hidden = false;
  if (byId('witness-grants')) byId('witness-grants').textContent = 'Current witness permission is unavailable.';
  if (byId('grant-description')) byId('grant-description').textContent = 'Current permission is unavailable. Refresh before reviewing a command.';
}
function action(id, label, operation) { byId(id)?.addEventListener('click', () => run(label, operation)); }
async function refresh() {
  records = await client.list();
  session = (await client.session()).session;
  if (!selectedId || !records.some(record => record.id === selectedId)) selectedId = session?.subject_id || records.at(-1)?.id || null;
  if (root.dataset.participantPage !== 'key') selectedId = session?.subject_id || null;
  home = session && current() ? await client.request(`/api/v1/agents/me/home?subject_id=${encode(session.subject_id)}`) : null;
  if (root.dataset.participantPage === 'key') renderKeys();
  else renderGrants();
}
function renderKeys() {
  byId('participant-retained').hidden = records.length === 0;
  byId('participant-create').hidden = records.some(record => !['revoked','superseded'].includes(record.status));
  const select = byId('participant-key');
  select.replaceChildren(...records.map(record => new Option(`${record.registration.display_name} · ${record.status.replaceAll('_', ' ')}`, record.id)));
  if (selectedId) select.value = selectedId;
  const record = current();
  if (record) {
    byId('participant-subject').textContent = record.id;
    byId('participant-public-key').textContent = record.public_key;
    byId('key-description').textContent = `Local key state: ${record.status.replaceAll('_', ' ')}. Public disclosure: ${record.registration.operator_backing.operator_id}.`;
    byId('participant-profile').href = `/agent/${encode(record.id)}`;
    byId('participant-enroll').hidden = !['retained', 'enrollment_pending'].includes(record.status);
    byId('participant-enroll').textContent = record.status === 'enrollment_pending' ? 'Retry control proof' : 'Prove control';
    byId('participant-signin').hidden = record.status !== 'active' || session?.subject_id === record.id;
    byId('participant-rotate').disabled = !['active', 'rotation_pending'].includes(record.status) || Boolean(record.predecessor_id && record.status === 'rotation_pending');
    byId('participant-rotate').textContent = record.status === 'rotation_pending' ? 'Retry key rotation' : 'Rotate to a new key';
    byId('participant-revoke').disabled = !['active', 'revocation_pending'].includes(record.status);
    byId('participant-revoke').textContent = record.status === 'revocation_pending' ? 'Retry retirement' : 'Retire key';
  }
  byId('participant-session').hidden = !session;
  if (session) byId('session-description').textContent = `${session.display_name} is signed in until ${session.expires_at}.`;
  message(session ? 'Signed in. A separate scoped grant is required to contribute.' : record ? 'Your key is retained here. Prove control or sign in when you choose.' : 'Ready to retain a key. Creation checks signing and storage support; review the storage limit first.');
}
function renderGrants() {
  const hasKey = Boolean(session && current() && home?.identity_status === 'active');
  if (root.dataset.participantPage === 'submit') {
    const available = hasKey ? grants('submit_seed') : [];
    chooseGrants('claim-grant', available);
    byId('claim-fields').disabled = !available.length || Boolean(draft);
    byId('claim-form').hidden = Boolean(draft);
    byId('claim-sign').disabled = !draft || !available.length;
    updateGrantDescription();
  } else {
    const target = root.dataset.targetSeed;
    const challenges = hasKey ? grants('submit_challenge', target) : [];
    const witnesses = hasKey ? grants('submit_witness_event', target) : [];
    chooseGrants('challenge-grant', challenges);
    byId('witness-grants').textContent = witnesses.length ? `Covering witness grants: ${witnesses.map(grant => `${grant.lease.scope} (expires ${grant.lease.expires_at})`).join('; ')}.` : 'No active covering witness grant for this claim.';
    byId('challenge-fields').disabled = !challenges.length || Boolean(draft);
    byId('witness-fields').disabled = !witnesses.length || Boolean(draft);
    byId('challenge-form').hidden = Boolean(draft); byId('witness-form').hidden = Boolean(draft);
    byId('contribution-sign').disabled = !draft || !(draft.kind === 'challenge' ? challenges.length : witnesses.length);
  }
  message(!hasKey ? 'Sign in with a retained, proved key to contribute.' : !home.active_authority_leases.length
    ? 'No current grant. Share your public identity and desired claim scope with this instance’s issuer, then refresh grants.'
    : 'Current grants are listed below. The server checks their scope and expiry again for each signed action.');
}
function updateGrantDescription() {
  const grant = grants('submit_seed').find(item => item.lease_id === byId('claim-grant')?.value);
  byId('grant-description').textContent = grant ? `Claim ${grant.lease.target_seed_id}. Issuer ${grant.lease.issuer_id}. Expires ${grant.lease.expires_at}.` : 'An issuer must grant submit permission for a specific claim identifier.';
}
function requireSession() {
  if (!session || !current() || home?.identity_status !== 'active') throw new Error('Active session and retained key required.');
}
async function checkSessionForDraft() {
  const observed = (await client.session()).session;
  if (!observed || observed.subject_id !== draft.keyId) throw new Error('Session changed.');
}
function showResult(id, text, href) {
  const node = byId(id), link = document.createElement('a');
  link.href = href; link.textContent = 'Inspect the claim dossier';
  node.replaceChildren(document.createTextNode(`${text} `), link);
  node.scrollIntoView({block:'nearest'});
}
function reviewDetails(entries) {
  const node = byId('claim-review-details'); node.replaceChildren();
  entries.forEach(([label, value]) => {
    const row = document.createElement('div'), dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = label; dd.textContent = value; row.append(dt, dd); node.append(row);
  });
}
function publicDownload(record) {
  const blob = new Blob([canonicalJSON({schema:'sab.browser_public_identity.v1', subject_id:record.id,
    public_key:record.public_key, registration:record.registration, local_custody_status:record.status, last_recorded_identity:record.identity,
    authority_effect:'none', standing_effect:'none'})], {type:'application/json'});
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = `${record.id}.public.json`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function setupKeys() {
  byId('participant-key').addEventListener('change', () => { selectedId = byId('participant-key').value; renderKeys(); });
  byId('participant-create-form').addEventListener('submit', event => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const registration = {display_name:field(form,'display_name'), operator_backing:{operator_id:field(form,'operator_id') || 'unknown',
      disclosure:field(form,'disclosure'), operator_kind:'unknown', backing_count_attestation:'unchecked'}};
    run('Retaining a key in this browser…', async () => {
      const record = await client.createKey(registration); selectedId = record.id;
      return 'Key retained. Choose “Prove control” to publish its public identity and signed proof.';
    });
  });
  action('participant-enroll', 'Checking and signing your control proof…', async () => { await client.enroll(selectedId); return 'Control proved. You can sign in; a grant is still required to contribute.'; });
  action('participant-signin', 'Signing a session request…', async () => {
    const accepted = await client.signIn(selectedId);
    const observed = (await client.session()).session;
    if (!observed || canonicalJSON(accepted) !== canonicalJSON(observed)) {
      const error = new Error('Session cookie unavailable.'); error.code = 'session_cookie_unavailable'; throw error;
    }
    return 'Signed in for six hours. Your key stays in this browser.';
  });
  action('participant-reconcile', 'Reading recorded key status…', async () => { await client.reconcile(selectedId); return 'Recorded status checked. Pending operations may still require an explicit retry.'; });
  action('participant-export', 'Preparing public identity…', async () => { publicDownload(current()); return 'Public identity downloaded. It contains no signing key and grants no authority.'; });
  action('participant-signout', 'Ending this session…', async () => { await client.signOut(session.csrf_token); return 'Signed out. Your key remains retained in this browser profile.'; });
  action('participant-rotate', 'Preparing and signing key rotation…', async () => {
    if (!byId('retire-ack').checked) return ['Select the retirement acknowledgement before rotating this key.', true];
    const registration = {...current().registration}; delete registration.public_key;
    const result = await client.rotate(selectedId, registration); selectedId = result.record.id; byId('retire-ack').checked = false;
    return 'Key rotated. Sign in with the successor, then obtain new grants. Historical grants did not transfer.';
  });
  action('participant-revoke', 'Signing retirement of this key…', async () => {
    if (!byId('retire-ack').checked) return ['Select the retirement acknowledgement before retiring this key.', true];
    await client.revoke(selectedId); byId('retire-ack').checked = false;
    return 'Key retired on this instance. It can no longer authorize a contribution or session.';
  });
}
function setupClaim() {
  byId('claim-grant').addEventListener('change', updateGrantDescription);
  byId('claim-form').addEventListener('submit', event => {
    event.preventDefault(); const form = event.currentTarget;
    if (!form.reportValidity()) return;
    run('Preparing your claim for review…', async () => {
      requireSession();
      const grant = grants('submit_seed').find(item => item.lease_id === field(form,'grant'));
      if (!grant) throw new Error('Grant changed.');
      const created = new Date().toISOString(), due = new Date(`${field(form,'due')}T00:00:00Z`);
      if (!Number.isFinite(due.valueOf()) || due <= new Date()) return ['Choose a future review date.', true];
      const seed = grant.lease.target_seed_id, identity = home.identity, backing = identity.operator_backing;
      const packet = {schema:'sab.seed_packet.v1', seed_id:seed, seed_type:'claim', title:field(form,'title'), status:'draft', loop_position:'spark', north_star:'deepen_truth',
        claim:{claim_id:`sab_claim_${seed.slice(9)}`, text:field(form,'text'), claim_type:field(form,'claim_type'), scope:field(form,'scope'), decision_context:field(form,'context'),
          success_conditions:[field(form,'success')], failure_conditions:[field(form,'failure')]},
        claimant_identity:{subject_id:identity.subject_id, identity_ref:identity.identity_ref},
        operator_backing:{operator_ref:backing.operator_id, disclosure:backing.disclosure || 'No backing disclosure provided.', concentration_attestation:'unchecked'},
        authority_lease:reference(grant), evidence_bundle:[{ref:field(form,'evidence'),kind:field(form,'evidence_kind'),privacy_class:'public'}],
        challenge_plan:{required:true,challenge_window:'P7D',strongest_objections:[field(form,'objection')],challenge_refs:[],falsification_routes:[field(form,'failure')],correction_path:`/api/v1/seeds/${seed}/correct`},
        witness_plan:{required_roles:['independent_reviewer'],minimum_witnesses:1,non_adjacent_required:true,forbidden_witnesses:[identity.subject_id]},
        build_plan:{artifact_refs:[field(form,'evidence')],production_grade_definition:'No production readiness claimed by this submission.'},
        anti_capture_rules:['A key, grant or submission alone confers no standing.','Unknown operator control cannot count as independent review.'],
        commons_return:{mode:'public_receipt',minimum_return:'Publish a record of any correction or withdrawal.'},
        canon_compost_policy:{canon_conditions:['Separate scoped review, resolved challenges and current independent evidence required.'],compost_conditions:['Withdraw or narrow if the stated failure condition is met.'],revalidation_due:due.toISOString()},
        privacy_class:'public',created_at:created};
      canonicalJSON(packet);
      draft = {kind:'seed', keyId:selectedId, packet};
      reviewDetails([['Title',packet.title],['Exact claim',packet.claim.text],['Scope',packet.claim.scope],['Would refute or narrow it',packet.claim.failure_conditions[0]],['Evidence reference',packet.evidence_bundle[0].ref],['Public operator declaration',`${backing.operator_id}: ${backing.disclosure || 'Not supplied'}`],['Permission',`${grant.lease.scope} · ${grant.lease.expires_at}`],['Review due',due.toISOString()]]);
      byId('claim-packet').textContent = JSON.stringify(packet,null,2); byId('claim-review').hidden = false; byId('review-heading').focus();
      return 'Review the exact claim and packet. Nothing has been signed or submitted yet.';
    });
  });
  action('claim-edit', 'Returning to editing…', async () => { draft = null; byId('claim-review').hidden = true; });
  action('claim-sign', 'Signing and submitting this reviewed claim…', async () => {
    if (!draft || draft.kind !== 'seed') return;
    await checkSessionForDraft();
    const packet = await client.signSeed(draft.keyId,draft.packet);
    const result = await client.request('/api/v1/seeds',{method:'POST',body:{seed_packet:packet,create_spark_projection:true}});
    if (result.accepted !== true || result.seed_id !== packet.seed_id) throw new Error('Unexpected receipt.');
    showResult('claim-result','Claim recorded. Reliance and standing remain unestablished.',`/claims/${encode(packet.seed_id)}`);
    draft = null; byId('claim-review').hidden = true;
    return 'Your signed claim is recorded. Inspect its dossier and invite scoped review through the instance’s operator workflow.';
  });
}
function setupContributions() {
  const seed = root.dataset.targetSeed, claim = root.dataset.targetClaim;
  for (const kind of ['challenge','witness']) byId(`${kind}-form`).addEventListener('submit', event => {
    event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return;
    run('Preparing your observation for review…', async () => {
      requireSession(); const created = new Date().toISOString(); let packet;
      if (kind === 'challenge') {
        const grant = grants('submit_challenge',seed).find(item => item.lease_id === field(form,'grant')); if (!grant) throw new Error('Grant unavailable.');
        packet = {schema:'sab.challenge_packet.v1',challenge_id:`sab_challenge_${crypto.randomUUID().replaceAll('-','')}`,target_seed_id:seed,target_claim_id:claim,
          challenger_identity:home.identity.identity_ref,quoted_claim_fragment:field(form,'quote'),challenge_type:'counterexample',
          evidence:[{ref:field(form,'evidence'),kind:'source',privacy_class:'public'}],proposed_falsification_or_narrowing:field(form,'argument'),severity:field(form,'severity'),
          deadline:new Date(Date.now()+7*86400000).toISOString(),created_at:created,authority_lease:reference(grant)};
      } else {
        if (!grants('submit_witness_event',seed).length) throw new Error('Grant unavailable.');
        const chain = await client.request(`/api/v1/seeds/${encode(seed)}/chain`);
        packet = {event_type:field(form,'action'),subject_type:'seed',subject_id:seed,payload:{note:field(form,'note')},prev_hash:chain.head,created_at:created};
      }
      draft = {kind,keyId:selectedId,packet};
      byId('contribution-summary').textContent = `${kind === 'challenge' ? 'Challenge' : packet.event_type === 'affirm' ? 'Affirm within scope' : 'Refuse affirmation'} for ${seed}. ${kind === 'challenge' ? packet.proposed_falsification_or_narrowing : packet.payload.note}`;
      byId('contribution-packet').textContent = JSON.stringify(packet,null,2); byId('contribution-review').hidden = false; byId('contribution-review').querySelector('h3').focus();
      return 'Review the exact target and observation before signing.';
    });
  });
  action('contribution-edit','Returning to editing…',async () => { draft = null; byId('contribution-review').hidden = true; });
  action('contribution-sign','Signing the reviewed observation…',async () => {
    if (!draft) return; await checkSessionForDraft();
    const kind = draft.kind, packet = kind === 'challenge' ? await client.signChallenge(draft.keyId,draft.packet) : await client.signWitness(draft.keyId,draft.packet);
    const result = await client.request(kind === 'challenge' ? `/api/v1/seeds/${encode(seed)}/challenges` : '/api/v1/witness-events', {method:'POST',body:kind === 'challenge' ? {challenge_packet:packet} : packet});
    if (kind === 'challenge' ? result.challenge_id !== packet.challenge_id : result.subject_id !== seed || result.event_type !== packet.event_type) throw new Error('Unexpected receipt.');
    draft = null; byId('contribution-review').hidden = true;
    showResult('contribution-result','Signed observation recorded.',`/claims/${encode(seed)}`);
    return 'Observation recorded. Review the updated dossier; this action does not establish standing.';
  });
}
async function start() {
  if (!root) return;
  try {
    client = await createParticipant({origin:location.origin});
    if (root.dataset.participantPage === 'key') setupKeys();
    else if (root.dataset.participantPage === 'submit') setupClaim();
    else setupContributions();
    action('participant-refresh','Refreshing current permission…',async () => { draft = null; byId('claim-review')?.setAttribute('hidden',''); byId('contribution-review')?.setAttribute('hidden',''); });
    await refresh(); root.querySelectorAll('[data-needs-support]').forEach(node => { node.disabled = false; });
  } catch (error) { clearCurrentPermission(); message(explain(error),true); }
}
start();
