import { useEffect, useMemo, useRef } from 'react';
import gsap from 'gsap';

export type SealState = 'ready' | 'intact' | 'cracked';

interface SealProps {
  state: SealState;
  stampKey: number;
}

function blobPath(): string {
  const points: string[] = [];
  const steps = 72;
  for (let step = 0; step <= steps; step += 1) {
    const angle = (step / steps) * Math.PI * 2;
    const radius = 108 + Math.sin(angle * 11) * 3.2 + Math.cos(angle * 5) * 2.4;
    const x = 130 + radius * Math.cos(angle);
    const y = 130 + radius * Math.sin(angle);
    points.push(`${step === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`);
  }
  return `${points.join(' ')}Z`;
}

const CRACK =
  'M132 24 L118 74 L139 96 L110 132 L134 154 L116 196 L128 236 M118 74 L96 92 M139 96 L158 112 M110 132 L88 146 M134 154 L156 166';

export function Seal({ state, stampKey }: SealProps) {
  const path = useMemo(blobPath, []);
  const root = useRef<SVGSVGElement>(null);
  const crack = useRef<SVGPathElement>(null);
  const reduce = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  useEffect(() => {
    if (!root.current || reduce) return;
    const stamp = gsap.fromTo(
      root.current,
      { scale: 1.18, rotate: -4, opacity: 0.4 },
      { scale: 1, rotate: 0, opacity: 1, duration: 0.55, ease: 'back.out(2)' },
    );
    return () => {
      stamp.kill();
    };
  }, [stampKey, reduce]);

  useEffect(() => {
    if (!crack.current || reduce) return;
    if (state !== 'cracked') {
      gsap.set(crack.current, { strokeDasharray: 0, strokeDashoffset: 0, opacity: 0 });
      return;
    }
    const length = crack.current.getTotalLength();
    const draw = gsap.fromTo(
      crack.current,
      { strokeDasharray: length, strokeDashoffset: length, opacity: 0.9 },
      { strokeDashoffset: 0, duration: 0.7, ease: 'power2.out' },
    );
    return () => {
      draw.kill();
    };
  }, [state, stampKey, reduce]);

  return (
    <svg
      ref={root}
      className={`seal seal--${state}`}
      viewBox="0 0 260 260"
      role="img"
      aria-label={
        state === 'intact'
          ? 'An intact wax seal: the signature verified'
          : state === 'cracked'
            ? 'A cracked wax seal: verification failed'
            : 'A wax seal waiting for a verification'
      }
    >
      <defs>
        <radialGradient id="wax" cx="38%" cy="30%" r="72%">
          <stop offset="0%" stopColor="#d26450" />
          <stop offset="52%" stopColor="#b23a2e" />
          <stop offset="100%" stopColor="#7d241c" />
        </radialGradient>
        <filter id="waxShadow" x="-30%" y="-30%" width="160%" height="160%">
          <feDropShadow dx="0" dy="10" stdDeviation="12" floodColor="#000" floodOpacity="0.5" />
        </filter>
      </defs>

      <path d={path} fill="url(#wax)" filter="url(#waxShadow)" />
      <path d={path} fill="none" stroke="#5f1a14" strokeWidth="1.4" opacity="0.7" />
      <circle cx="130" cy="130" r="86" fill="none" stroke="#5f1a14" strokeWidth="1.6" opacity="0.45" />
      <circle cx="130" cy="130" r="76" fill="none" stroke="#f0c9b8" strokeWidth="0.8" opacity="0.28" />

      <text x="130" y="154" textAnchor="middle" className="seal__letter">
        S
      </text>
      <text x="130" y="186" textAnchor="middle" className="seal__caption">
        sigcheck
      </text>

      <path ref={crack} d={CRACK} fill="none" stroke="#2a0d0a" strokeWidth="3.4" strokeLinecap="round" opacity="0" />
    </svg>
  );
}
