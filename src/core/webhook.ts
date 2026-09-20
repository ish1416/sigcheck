/**
 * Webhook signature verification, Stripe style:
 *
 *   Stripe-Signature: t=1730000000,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd
 *
 * The signed payload is `${t}.${rawBody}`. The body must be the exact bytes that were sent:
 * re-serialising the JSON changes the bytes and the signature stops matching.
 */

export interface ParsedHeader {
  timestamp: number | null;
  signatures: string[];
  malformed: boolean;
}

export interface Check {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface VerifyInput {
  payload: string;
  header: string;
  secret: string;
  toleranceSeconds: number;
  now: number;
  /** Signatures already accepted, for replay detection. */
  seen: Set<string>;
}

export interface VerifyResult {
  ok: boolean;
  checks: Check[];
  computed: string | null;
  parsed: ParsedHeader;
}

const encoder = new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return toHex(signature);
}

/** Compare two hex strings without exiting at the first differing character. */
export function constantTimeEqual(left: string, right: string): boolean {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

export function parseHeader(header: string): ParsedHeader {
  const parts = header.split(',').map((part) => part.trim());
  let timestamp: number | null = null;
  const signatures: string[] = [];

  for (const part of parts) {
    const [key, value] = part.split('=');
    if (key === 't' && value) {
      const parsed = Number(value);
      if (Number.isInteger(parsed) && parsed > 0) timestamp = parsed;
    }
    if (key === 'v1' && value) signatures.push(value);
  }

  return {
    timestamp,
    signatures,
    malformed: timestamp === null || signatures.length === 0 || parts.some((part) => !part.includes('=')),
  };
}

export async function signPayload(secret: string, timestamp: number, payload: string): Promise<string> {
  return hmacSha256Hex(secret, `${timestamp}.${payload}`);
}

export function formatHeader(timestamp: number, signature: string): string {
  return `t=${timestamp},v1=${signature}`;
}

export async function verifyWebhook(input: VerifyInput): Promise<VerifyResult> {
  const parsed = parseHeader(input.header);
  const checks: Check[] = [];

  checks.push({
    id: 'format',
    label: 'Header parses',
    passed: !parsed.malformed,
    detail: parsed.malformed
      ? 'Expected t=<unix seconds>,v1=<hex digest>. A malformed header must be rejected before any crypto runs.'
      : `Timestamp ${parsed.timestamp}, ${parsed.signatures.length} signature(s).`,
  });

  const ageSeconds = parsed.timestamp === null ? Number.POSITIVE_INFINITY : Math.abs(input.now - parsed.timestamp);
  const fresh = parsed.timestamp !== null && ageSeconds <= input.toleranceSeconds;
  checks.push({
    id: 'timestamp',
    label: 'Timestamp inside tolerance',
    passed: fresh,
    detail:
      parsed.timestamp === null
        ? 'No timestamp to check.'
        : `${Math.round(ageSeconds)} s old, tolerance ${input.toleranceSeconds} s. An old signature is a replay with extra steps.`,
  });

  const computed = parsed.timestamp === null ? null : await signPayload(input.secret, parsed.timestamp, input.payload);
  const matched = computed !== null && parsed.signatures.some((candidate) => constantTimeEqual(computed, candidate));
  checks.push({
    id: 'signature',
    label: 'Signature matches the bytes',
    passed: matched,
    detail: matched
      ? 'HMAC-SHA256 over `${timestamp}.${rawBody}` matches one of the v1 signatures.'
      : 'A single changed byte changes the digest. Re-serialising the JSON changes the bytes.',
  });

  const replay = matched && parsed.signatures.some((candidate) => input.seen.has(candidate));
  checks.push({
    id: 'replay',
    label: 'Not seen before',
    passed: matched && !replay,
    detail: !matched
      ? 'Replay is only meaningful once the signature is valid.'
      : replay
        ? 'This exact signature was already accepted, so this is a replay.'
        : 'The signature has not been accepted before.',
  });

  const ok = checks.every((check) => check.passed);
  if (ok && computed) {
    input.seen.add(computed);
  }

  return { ok, checks, computed, parsed };
}
