/**
 * L0 - hello-world escrow oracle (JavaScript)
 *
 * Minimal spec-conformant oracle. Same semantics as the Python
 * reference at examples/hello-oracle.py, translated to Node.js.
 *
 * Demonstrates:
 *   - reading a PaymentOffer url_check policy
 *   - running the deterministic check
 *   - constructing the canonical attestation transcript
 *   - signing with an ephemeral key derived from a master key
 *
 * Run:
 *   node examples/hello-oracle.js --request-id req-7f3e --policy-url https://httpbin.org/status/200
 *
 * Expected output:
 *   [oracle] check passed: true
 *   [oracle] ephemeral pubkey: 0x...
 *   [oracle] attestation bytes: 0x...
 */

const crypto = require('crypto');
const https = require('https');
const http = require('http');

const DOMAIN = Buffer.from('escrow-oracles/v1\0', 'utf8');
const TYPE_TAG_ATTESTATION = Buffer.from([0x01]);
const EPOCH_SECONDS = 86_400;

function masterKey() {
  const raw = process.env.ORACLE_MASTER_KEY_HEX;
  if (raw) return Buffer.from(raw, 'hex');
  console.error('[oracle] no ORACLE_MASTER_KEY_HEX; generating ephemeral master');
  return crypto.randomBytes(32);
}

function deriveEphemeral(master, requestId, epochId) {
  const h = crypto.createHash('sha256');
  h.update(master);
  h.update(Buffer.from('|'));
  h.update(Buffer.from(requestId));
  h.update(Buffer.from('|'));
  const buf = Buffer.alloc(8);
  buf.writeBigUint64BE(BigInt(epochId));
  h.update(buf);
  return h.digest();
}

function ephemeralPubkey(ephemeralPriv) {
  const h = crypto.createHash('sha256');
  h.update(ephemeralPriv);
  h.update(Buffer.from('pub'));
  return h.digest();
}

function sign(ephemeralPriv, digest) {
  const h = crypto.createHash('sha256');
  h.update(Buffer.from('sig\0'));
  h.update(ephemeralPriv);
  h.update(digest);
  return h.digest();
}

function runUrlCheck(policy) {
  return new Promise((resolve) => {
    const url = new URL(policy.url);
    const method = policy.method || 'GET';
    const timeout = policy.max_latency_ms || 30000;
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, { method, timeout }, (res) => {
      let body = [];
      res.on('data', c => body.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          body: Buffer.concat(body),
          ok: res.statusCode >= 200 && res.statusCode < 300,
        });
      });
    });
    req.on('error', e => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.end();
  });
}

async function main() {
  const args = {};
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i].startsWith('--')) {
      const k = process.argv[i].slice(2);
      args[k] = process.argv[i + 1];
      i++;
    }
  }
  const requestId = args['request-id'] || 'req-7f3e';
  const policyUrl = args['policy-url'] || 'https://httpbin.org/status/200';
  const epochId = Math.floor(Date.now() / 1000 / EPOCH_SECONDS);
  const master = masterKey();
  const ephemeral = deriveEphemeral(master, requestId, epochId);
  const pubkey = ephemeralPubkey(ephemeral);

  const policy = { url: policyUrl, method: 'GET', max_latency_ms: 30000 };
  const result = await runUrlCheck(policy);
  const checkPassed = result.ok;

  console.log('[oracle] check passed:', checkPassed);
  console.log('[oracle] ephemeral pubkey: 0x' + pubkey.toString('hex'));
  console.log('[oracle] request-id:', requestId);
  console.log('[oracle] fetch result:', result.ok ? 'success' : result.error);

  const attestation = JSON.stringify({
    request_id: requestId,
    policy_hash: crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex'),
    check_result: checkPassed,
    observed_at_unix: Math.floor(Date.now() / 1000),
    oracle_pubkey_ephemeral: '0x' + pubkey.toString('hex'),
    chain_id: 0,
    registry_address: '0x0000000000000000000000000000000000000000',
  }, Object.keys({ request_id:0, policy_hash:0, check_result:0, observed_at_unix:0, oracle_pubkey_ephemeral:0, chain_id:0, registry_address:0 }).sort());

  const transcript = Buffer.concat([DOMAIN, TYPE_TAG_ATTESTATION, Buffer.from(attestation)]);
  const digest = crypto.createHash('sha256').update(transcript).digest();
  const sig = sign(ephemeral, digest);

  console.log('[oracle] attestation bytes: 0x' + sig.toString('hex'));
}

main().catch(e => console.error('[oracle] error:', e.message));
