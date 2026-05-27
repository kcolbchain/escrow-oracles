#!/usr/bin/env npx tsx
/**
 * L0 — hello-world escrow oracle (TypeScript port)
 *
 * Port of examples/hello-oracle.py to TypeScript.
 * Run: npx tsx examples/hello-oracle.ts --request-id req-7f3e --policy-url https://httpbin.org/status/200
 *
 * Requires: Node.js 18+ (native fetch) or Deno / Bun
 * Zero npm dependencies.
 */

import crypto from "node:crypto";

const DOMAIN = Buffer.from("escrow-oracles/v1\0");
const TYPE_TAG_ATTESTATION = Buffer.from([0x01]);
const EPOCH_SECONDS = 86_400;

function masterKey(): Buffer {
  const raw = process.env["ORACLE_MASTER_KEY_HEX"];
  if (raw) return Buffer.from(raw, "hex");
  console.log("[oracle] no ORACLE_MASTER_KEY_HEX; generating ephemeral master");
  return crypto.randomBytes(32);
}

function deriveEphemeral(master: Buffer, requestId: string, epochId: number): Buffer {
  const h = crypto.createHash("shake256", { outputLength: 32 });
  h.update(master);
  h.update(Buffer.from("|"));
  h.update(Buffer.from(requestId));
  h.update(Buffer.from("|"));
  const epochBuf = Buffer.alloc(8);
  epochBuf.writeBigInt64BE(BigInt(epochId), 0);
  h.update(epochBuf);
  return h.digest();
}

function ephemeralPubkey(ephemeralPriv: Buffer): Buffer {
  const h = crypto.createHash("sha256");
  h.update(ephemeralPriv);
  h.update(Buffer.from("pub"));
  return h.digest();
}

function sign(ephemeralPriv: Buffer, digest: Buffer): Buffer {
  const h = crypto.createHash("shake256", { outputLength: 64 });
  h.update(Buffer.from("sig\0"));
  h.update(ephemeralPriv);
  h.update(digest);
  return h.digest();
}

interface Policy {
  checks: Array<{
    type: string;
    url: string;
    method?: string;
    expect_status?: number;
    max_latency_ms?: number;
    expect_body_hash?: string;
  }>;
}

async function runUrlCheck(policy: Policy["checks"][number]): Promise<boolean> {
  const deadlineMs = policy.max_latency_ms ?? 30_000;
  const started = Date.now();
  try {
    const resp = await fetch(policy.url, { method: policy.method ?? "GET", signal: AbortSignal.timeout(deadlineMs) });
    const elapsedMs = Date.now() - started;
    if (elapsedMs > deadlineMs) {
      console.log(`[oracle] over latency budget (${elapsedMs}ms > ${deadlineMs}ms)`);
      return false;
    }
    if (resp.status !== (policy.expect_status ?? 200)) {
      console.log(`[oracle] status mismatch (${resp.status} != ${policy.expect_status ?? 200})`);
      return false;
    }
    if (policy.expect_body_hash) {
      const body = await resp.arrayBuffer();
      const bodyHash = "0x" + crypto.createHash("sha256").update(Buffer.from(body)).digest("hex");
      if (bodyHash !== policy.expect_body_hash) {
        console.log(`[oracle] body hash mismatch`);
        return false;
      }
    }
    return true;
  } catch (err) {
    console.log(`[oracle] fetch failed: ${err}`);
    return false;
  }
}

function canonicalJson(obj: Record<string, unknown>): Buffer {
  const keys = Object.keys(obj).sort();
  const parts = keys.map(k => JSON.stringify(k) + ":" + JSON.stringify(obj[k]));
  return Buffer.from("{" + parts.join(",") + "}");
}

interface Attestation {
  request_id: string;
  policy_hash: string;
  check_result: boolean;
  observed_at: number;
  oracle_pubkey: string;
  signature: string;
}

async function attest(
  requestId: string, policy: Policy, master: Buffer,
  registryAddress: string, chainId: number
): Promise<Attestation> {
  const epochId = Math.floor(Date.now() / 1000 / EPOCH_SECONDS);
  const ephemeralPriv = deriveEphemeral(master, requestId, epochId);
  const ephemeralPub = ephemeralPubkey(ephemeralPriv);

  const policyJson = JSON.stringify(policy, Object.keys(policy).sort());
  const policyHash = "0x" + crypto.createHash("sha256").update(policyJson).digest("hex");

  const checkResult = await runUrlCheck(policy.checks[0]);
  const observedAt = Math.floor(Date.now() / 1000);

  const canonDict: Record<string, unknown> = {
    request_id: requestId,
    policy_hash: policyHash,
    check_result: checkResult,
    observed_at_unix: observedAt,
    oracle_pubkey_ephemeral: "0x" + ephemeralPub.toString("hex"),
    chain_id: chainId,
    registry_address: registryAddress,
  };
  const canon = canonicalJson(canonDict);

  const transcript = Buffer.concat([DOMAIN, TYPE_TAG_ATTESTATION, canon]);
  const digest = crypto.createHash("shake256", { outputLength: 64 }).update(transcript).digest();
  const signature = sign(ephemeralPriv, digest);

  return {
    request_id: requestId,
    policy_hash: policyHash,
    check_result: checkResult,
    observed_at: observedAt,
    oracle_pubkey: "0x" + ephemeralPub.toString("hex"),
    signature: "0x" + signature.toString("hex"),
  };
}

function usage() {
  console.log(`Usage: npx tsx examples/hello-oracle.ts --request-id <id> --policy-url <url>`);
  process.exit(1);
}

async function main() {
  const args = process.argv.slice(2);
  const getArg = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
  };

  const requestId = getArg("--request-id") ?? usage();
  const policyUrl = getArg("--policy-url") ?? usage();
  const registry = getArg("--registry") ?? "0x" + "0".repeat(40);
  const chainId = parseInt(getArg("--chain-id") ?? "8453", 10);

  const policy: Policy = {
    checks: [{
      type: "url_check",
      url: policyUrl,
      method: "GET",
      expect_status: 200,
      max_latency_ms: 30_000,
    }],
  };

  const master = masterKey();
  const att = await attest(requestId, policy, master, registry, chainId);

  console.log(`[oracle] check passed: ${att.check_result}`);
  console.log(`[oracle] ephemeral pubkey: ${att.oracle_pubkey}`);
  console.log(`[oracle] attestation: ${JSON.stringify(att, null, 2)}`);
  process.exit(att.check_result ? 0 : 1);
}

main();
