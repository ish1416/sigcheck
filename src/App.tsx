import { useEffect, useMemo, useRef, useState } from 'react';
import { Seal, type SealState } from './components/Seal';
import { formatHeader, signPayload, verifyWebhook, type VerifyResult } from './core/webhook';

const DEFAULT_BODY = `{
  "id": "evt_9f2c",
  "type": "charge.succeeded",
  "amount": 129900,
  "currency": "inr",
  "merchant": "mch_kettle"
}`;

const DEFAULT_SECRET = 'whsec_demo_kettle_2026';
const BASE_TIME = Math.floor(Date.now() / 1000) - 24;

export default function App() {
  const [body, setBody] = useState(DEFAULT_BODY);
  const [signedBody, setSignedBody] = useState(DEFAULT_BODY);
  const [secret, setSecret] = useState(DEFAULT_SECRET);
  const [timestamp, setTimestamp] = useState(BASE_TIME);
  const [tolerance, setTolerance] = useState(300);
  const [clockOffset, setClockOffset] = useState(0);
  const [seen, setSeen] = useState<Set<string>>(new Set());
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [stampKey, setStampKey] = useState(0);
  const [header, setHeader] = useState('');
  const timer = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    signPayload(secret, timestamp, signedBody).then((signature) => {
      if (!cancelled) setHeader(formatHeader(timestamp, signature));
    });
    return () => {
      cancelled = true;
    };
  }, [secret, timestamp, signedBody]);

  useEffect(() => {
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, []);

  const tampered = body !== signedBody;
  const sealState: SealState = result === null ? 'ready' : result.ok ? 'intact' : 'cracked';
  const failed = result?.checks.filter((check) => !check.passed) ?? [];

  const summary = useMemo(() => {
    if (!result) return 'Not verified yet.';
    if (result.ok) return 'Accepted. The event is genuine and has not been seen before.';
    return `Rejected: ${failed.map((check) => check.label.toLowerCase()).join(', ')}.`;
  }, [result, failed]);

  function invalidate() {
    setResult(null);
    if (timer.current) window.clearTimeout(timer.current);
  }

  async function verify() {
    setBusy(true);
    const nextSeen = new Set(seen);
    const outcome = await verifyWebhook({
      payload: body,
      header,
      secret,
      toleranceSeconds: tolerance,
      now: Math.floor(Date.now() / 1000) + clockOffset,
      seen: nextSeen,
    });
    setResult(outcome);
    setSeen(nextSeen);
    setStampKey((value) => value + 1);
    setBusy(false);
  }

  function replay() {
    if (!result?.ok) return;
    verifyWebhook({
      payload: body,
      header,
      secret,
      toleranceSeconds: tolerance,
      now: Math.floor(Date.now() / 1000) + clockOffset,
      seen,
    }).then((outcome) => {
      setResult(outcome);
      setStampKey((value) => value + 1);
    });
  }

  function tamper() {
    setBody((value) => value.replace('"amount": 129900', '"amount": 129999'));
    invalidate();
  }

  function reset() {
    setBody(DEFAULT_BODY);
    setSignedBody(DEFAULT_BODY);
    setSecret(DEFAULT_SECRET);
    setTimestamp(BASE_TIME);
    setTolerance(300);
    setClockOffset(0);
    setSeen(new Set());
    setResult(null);
  }

  return (
    <div className="shell">
      <a className="skip" href="#lab">
        Skip to the lab
      </a>

      <header className="masthead">
        <a className="wordmark" href="#top">
          Sigcheck
        </a>
        <nav className="nav" aria-label="Primary">
          <a href="#lab">Lab</a>
          <a href="#why">Why</a>
          <a href="#limits">Limits</a>
        </nav>
        <p className="masthead__meta">hmac-sha256 · in this tab</p>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero__copy">
            <p className="kicker">Webhook signatures · a seal for your events</p>
            <h1 className="display">
              A signature is
              <br className="display__br" />{' '}
              a wax seal.
            </h1>
            <p className="hero__lede">
              Anyone can post JSON to your endpoint. A signature is the one part an attacker cannot forge without the
              secret, and the one part most integrations verify carelessly. Break the seal below and watch which check
              catches it.
            </p>
          </div>
          <div className="hero__seal">
            <Seal state={sealState} stampKey={stampKey} />
            <p className={`seal__verdict ${result?.ok ? 'is-good' : result ? 'is-bad' : ''}`}>{summary}</p>
          </div>
        </section>

        <section className="lab" id="lab" aria-labelledby="lab-title">
          <div className="lab__head">
            <h2 id="lab-title">The delivery</h2>
            <p>
              The header is signed over the exact bytes of the body. Re-serialising the JSON, or trimming a space,
              changes the digest.
            </p>
          </div>

          <div className="lab__grid">
            <div className="delivery">
              <div className="field">
                <label className="kicker" htmlFor="body">
                  Request body
                </label>
                <textarea
                  id="body"
                  value={body}
                  spellCheck={false}
                  rows={9}
                  onChange={(event) => {
                    setBody(event.target.value);
                    invalidate();
                  }}
                />
                {tampered && <p className="hint is-bad">The body no longer matches the signed bytes.</p>}
              </div>

              <div className="field">
                <span className="kicker">Stripe-Signature</span>
                <p className="header mono">{header || 'signing…'}</p>
              </div>

              <div className="fields">
                <label className="field">
                  <span className="kicker">Signing secret</span>
                  <input
                    type="text"
                    value={secret}
                    spellCheck={false}
                    onChange={(event) => {
                      setSecret(event.target.value);
                      invalidate();
                    }}
                  />
                </label>
                <label className="field">
                  <span className="kicker">Tolerance, seconds</span>
                  <input
                    type="number"
                    min={0}
                    max={86400}
                    value={tolerance}
                    onChange={(event) => {
                      setTolerance(Math.max(0, Number(event.target.value) || 0));
                      invalidate();
                    }}
                  />
                </label>
              </div>

              <div className="actions">
                <button className="button" type="button" onClick={verify} disabled={busy || !header}>
                  {busy ? 'Checking…' : 'Verify delivery'}
                  <span aria-hidden="true">→</span>
                </button>
                <button className="button button--ghost" type="button" onClick={tamper}>
                  Change one rupee
                </button>
                <button className="button button--ghost" type="button" onClick={() => { setClockOffset((value) => value + 3600); invalidate(); }}>
                  Wait an hour
                </button>
                <button className="button button--ghost" type="button" onClick={replay} disabled={!result?.ok}>
                  Send it again
                </button>
              </div>

              <div className="actions actions--quiet">
                <button className="link-button" type="button" onClick={() => { setSignedBody(body); setResult(null); }}>
                  Re-sign the current body
                </button>
                <button className="link-button" type="button" onClick={reset}>
                  Reset
                </button>
                {clockOffset > 0 && (
                  <span className="mono clock">clock +{Math.round(clockOffset / 60)} min</span>
                )}
              </div>
            </div>

            <aside className="checks" aria-label="Verification checks" aria-live="polite">
              <div className="checks__head">
                <p className="kicker">Four checks, in order</p>
                <p className={`checks__state ${result?.ok ? 'is-good' : result ? 'is-bad' : ''}`}>
                  {result ? (result.ok ? 'accepted' : 'rejected') : 'waiting'}
                </p>
              </div>

              <ol>
                {(result?.checks ?? PLACEHOLDER_CHECKS).map((check) => (
                  <li key={check.id} className={result ? (check.passed ? 'check is-pass' : 'check is-fail') : 'check'}>
                    <span className="check__mark" aria-hidden="true">
                      {result ? (check.passed ? '✓' : '×') : '·'}
                    </span>
                    <div>
                      <p className="check__label">{check.label}</p>
                      <p className="check__detail">{check.detail}</p>
                    </div>
                  </li>
                ))}
              </ol>

              <p className="checks__note">
                Comparison runs in constant time. A byte-by-byte `===` returns faster on the first wrong character, and
                that difference is enough to guess a digest one byte at a time.
              </p>
            </aside>
          </div>
        </section>

        <section className="why" id="why" aria-labelledby="why-title">
          <div className="why__head">
            <h2 id="why-title">Why the seal, and not a checksum</h2>
            <p>
              A checksum proves the bytes arrived intact. An HMAC proves they came from someone who holds the secret.
              The difference matters because webhook endpoints are public by design.
            </p>
          </div>
          <div className="why__grid">
            <article>
              <p className="kicker">01 · Raw bytes</p>
              <h3>Verify before parsing</h3>
              <p>
                `JSON.parse` followed by `JSON.stringify` reorders whitespace and can change number formatting. The
                signature covers bytes, so the bytes are what must be hashed.
              </p>
            </article>
            <article>
              <p className="kicker">02 · Timestamp</p>
              <h3>Old signatures are replays</h3>
              <p>
                A valid signature is valid forever unless the verifier checks when it was made. Five minutes is the
                usual tolerance; anything older is refused before the crypto runs.
              </p>
            </article>
            <article>
              <p className="kicker">03 · Comparison</p>
              <h3>Constant time, every byte</h3>
              <p>
                String equality exits at the first mismatch. An attacker who can time the endpoint can learn the digest
                one character at a time, which is why the comparison above never exits early.
              </p>
            </article>
            <article>
              <p className="kicker">04 · Replay</p>
              <h3>A signature is a one-time seal</h3>
              <p>
                Even inside the tolerance, the same delivery must not be processed twice. Recording accepted signatures
                turns a replay into a quiet duplicate.
              </p>
            </article>
          </div>
        </section>

        <section className="limits" id="limits">
          <h2>What this is not</h2>
          <div>
            <p>
              This is a browser implementation of a server-side check. It uses the Web Crypto API for HMAC-SHA256,
              which is the real algorithm, but a production receiver also needs a shared store for seen signatures and
              a clock that is not the user's.
            </p>
            <p>
              The secret here is a demo string typed into a page that never sends it anywhere. Do not put a real signing
              secret in a browser.
            </p>
          </div>
        </section>
      </main>

      <footer className="footer">
        <p className="footer__mark">Sigcheck</p>
        <p className="footer__line">A wax seal for webhook deliveries. Built by Ishita Singh, 2026.</p>
        <p className="footer__fine">
          <a className="link" href="https://github.com/ish1416/sigcheck">
            github.com/ish1416/sigcheck
          </a>{' '}
          · Not affiliated with Stripe. Demo secret only.
        </p>
      </footer>
    </div>
  );
}

const PLACEHOLDER_CHECKS = [
  { id: 'format', label: 'Header parses', passed: false, detail: 'Run a verification to see the header parsed.' },
  { id: 'timestamp', label: 'Timestamp inside tolerance', passed: false, detail: 'Freshness is checked before the digest.' },
  { id: 'signature', label: 'Signature matches the bytes', passed: false, detail: 'HMAC-SHA256 over timestamp and raw body.' },
  { id: 'replay', label: 'Not seen before', passed: false, detail: 'The same delivery must not be processed twice.' },
];
