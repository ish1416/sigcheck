# Sigcheck

**A wax seal for webhook signatures.**

A live lab for the four checks a webhook receiver must get right: the header parses, the timestamp
is inside tolerance, the HMAC matches the exact bytes, and the delivery has not been seen before.
Break the seal and see which check catches it.

Live: **https://site-2bec011ae68c4a229ac683fafc49cf67.freebuff.page**

## Why

Webhook endpoints are public by design, so authenticity has to be proved on every request. Most
integrations check the digest and stop there. That leaves three holes: re-serialised JSON changes
the signed bytes, an old signature is valid forever without a timestamp check, and a valid
signature can be replayed. Sigcheck makes each hole visible and closes it.

## The four checks

1. **Format.** `t=<unix seconds>,v1=<hex>` is parsed before any crypto runs. A malformed header is
   rejected early.
2. **Timestamp.** The signature is refused if it is older than the tolerance. Five minutes is the
   usual window.
3. **Signature.** HMAC-SHA256 over `${timestamp}.${rawBody}`, compared in constant time. A single
   changed byte changes the digest.
4. **Replay.** Accepted signatures are recorded, so the same delivery cannot be processed twice.

## Run

```bash
npm install
npm test      # 11 tests, including RFC 4231 HMAC vectors
npm run dev
npm run build
```

The demo uses the Web Crypto API in your browser. Nothing is sent anywhere, and the demo secret is
not a real one.

## Tests

- RFC 4231 test case 2 for HMAC-SHA256.
- Constant-time comparison on equal, unequal and different-length strings.
- Header parsing, including a missing timestamp.
- A valid delivery, a single-byte tamper, a stale timestamp, a replay and a wrong secret.

## Limits

This runs in the browser with the user's clock and an in-memory replay set. A production receiver
needs a shared store for seen signatures, a trusted clock, and a secret that never reaches the
client.

## License

MIT. See [LICENSE](LICENSE).

Built by [Ishita Singh](https://github.com/ish1416).
