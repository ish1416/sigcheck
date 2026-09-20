import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  formatHeader,
  hmacSha256Hex,
  parseHeader,
  signPayload,
  verifyWebhook,
} from './webhook';

const SECRET = 'whsec_test_do_not_use_in_production';
const BODY = '{"id":"evt_1","type":"charge.succeeded","amount":129900}';
const NOW = 1_790_000_000;

async function validInput(overrides: Partial<Parameters<typeof verifyWebhook>[0]> = {}) {
  const signature = await signPayload(SECRET, NOW, BODY);
  return {
    payload: BODY,
    header: formatHeader(NOW, signature),
    secret: SECRET,
    toleranceSeconds: 300,
    now: NOW,
    seen: new Set<string>(),
    ...overrides,
  };
}

describe('hmac', () => {
  it('matches RFC 4231 test case 2', async () => {
    expect(await hmacSha256Hex('Jefe', 'what do ya want for nothing?')).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  it('is stable for the same input and different for another', async () => {
    const first = await hmacSha256Hex(SECRET, BODY);
    expect(await hmacSha256Hex(SECRET, BODY)).toBe(first);
    expect(await hmacSha256Hex(SECRET, `${BODY} `)).not.toBe(first);
  });
});

describe('constant time comparison', () => {
  it('compares equal and unequal strings', () => {
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'ab')).toBe(false);
    expect(constantTimeEqual('', '')).toBe(true);
  });
});

describe('header parsing', () => {
  it('reads the timestamp and every v1 signature', () => {
    const parsed = parseHeader(`t=123,v1=aaa,v1=bbb`);
    expect(parsed.timestamp).toBe(123);
    expect(parsed.signatures).toEqual(['aaa', 'bbb']);
    expect(parsed.malformed).toBe(false);
  });

  it('flags a header with no timestamp', () => {
    expect(parseHeader('v1=aaa').malformed).toBe(true);
  });
});

describe('verification', () => {
  it('accepts a correctly signed payload', async () => {
    const result = await verifyWebhook(await validInput());
    expect(result.ok).toBe(true);
    expect(result.checks.every((check) => check.passed)).toBe(true);
  });

  it('rejects a single changed byte', async () => {
    const input = await validInput();
    const result = await verifyWebhook({ ...input, payload: `${BODY} ` });
    expect(result.ok).toBe(false);
    expect(result.checks.find((check) => check.id === 'signature')?.passed).toBe(false);
  });

  it('rejects a timestamp outside the tolerance', async () => {
    const input = await validInput();
    const result = await verifyWebhook({ ...input, now: NOW + 301 });
    expect(result.ok).toBe(false);
    expect(result.checks.find((check) => check.id === 'timestamp')?.passed).toBe(false);
  });

  it('rejects a replayed signature', async () => {
    const input = await validInput();
    const seen = new Set<string>();
    const first = await verifyWebhook({ ...input, seen });
    expect(first.ok).toBe(true);
    const second = await verifyWebhook({ ...input, seen });
    expect(second.ok).toBe(false);
    expect(second.checks.find((check) => check.id === 'replay')?.passed).toBe(false);
  });

  it('rejects a wrong secret', async () => {
    const input = await validInput();
    const result = await verifyWebhook({ ...input, secret: 'whsec_wrong' });
    expect(result.ok).toBe(false);
  });

  it('rejects a malformed header without throwing', async () => {
    const result = await verifyWebhook({ ...(await validInput()), header: 'nonsense' });
    expect(result.ok).toBe(false);
    expect(result.checks.find((check) => check.id === 'format')?.passed).toBe(false);
  });
});
