# Sigcheck — the beginner's guide

## 1. What is this thing?

Stripe, Razorpay and every other payment API send **webhooks**: an HTTP POST to your server saying
"this payment succeeded". Your endpoint is public, so anyone can POST to it. The only thing that
proves a message really came from Stripe is a **signature**: a hash of the message, computed with a
secret only the two of you know.

Sigcheck is a lab where you break the seal on purpose and watch which of the four checks catches you.

## 2. The one idea

> A signature is a wax seal: it proves the letter was closed by the sender, and only if you check it
> against the exact bytes they sealed.

## 3. The four checks

| # | Check | What it catches |
| --- | --- | --- |
| 1 | Header format `t=...,v1=...` | malformed or missing signature, before any crypto |
| 2 | Timestamp inside tolerance (5 min) | an old signature replayed tomorrow |
| 3 | HMAC-SHA256 over `${t}.${rawBody}`, constant-time compare | a single changed byte |
| 4 | Replay store | the same valid delivery sent twice |

The order matters: cheap checks first, crypto third, state last.

## 4. Why raw bytes

If you parse the JSON and re-serialise it, key order and whitespace can change, and the bytes you
hash are no longer the bytes that were signed. That is why the check reads `await request.text()`
before `JSON.parse`, and why the demo hashes the textarea contents exactly as typed.

## 5. Files

| File | What it is |
| --- | --- |
| `src/core/webhook.ts` | Parse, verify, replay-check. Pure functions with Web Crypto. |
| `src/core/webhook.test.ts` | 11 tests, including RFC 4231 vectors. |
| `src/components/Seal.tsx` | The wax seal drawn from the digest. |
| `src/App.tsx` | The lab: body, secret, timestamp, run, results. |

## 6. Run it

```bash
npm install
npm test
npm run dev
```

## 7. Words you will meet

| Word | Meaning here |
| --- | --- |
| **HMAC** | A hash keyed with a secret; only someone with the secret can produce it. |
| **Constant-time compare** | Comparing without early exit, so timing does not leak the answer. |
| **Tolerance window** | How old a timestamp may be before it is refused. |
| **Replay** | Sending a valid message again later. |
| **Raw body** | The exact bytes received, before parsing. |

## 8. Try these

1. Change one character in the body. Confirm the digest changes completely (avalanche effect).
2. Keep the body identical but move the timestamp back an hour. Which check fires, and why is that
   separate from the signature?
3. Sign a message, then pretty-print the JSON before verifying. Explain why verification fails even
   though the data is "the same".
4. Read `timingSafeEqual`. Replace it with `===` and describe the attack that becomes possible.

## 9. Limits

The demo runs in your browser with your own clock and an in-memory replay set. A real receiver needs
a shared store for seen signatures, a trusted clock, and a secret that never reaches the browser.
