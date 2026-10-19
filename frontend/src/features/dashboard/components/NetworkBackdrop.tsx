// Role 4: still red/blue particle network behind the dashboard hero, in the landing page's dither style.
// Drawn once per resize on a 2D canvas, so it adds atmosphere without a render loop. Decorative only.
import { useEffect, useRef } from "react";

type RGB = [number, number, number];

const BLUE: RGB = [72, 150, 255];
const RED: RGB = [255, 48, 78];
const VIOLET: RGB = [150, 110, 255];

const mulberry32 = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const rgba = ([r, g, b]: RGB, a: number) => `rgba(${r},${g},${b},${a})`;

function draw(canvas: HTMLCanvasElement) {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  if (!w || !h) return;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  ctx.globalCompositeOperation = "lighter";
  const random = mulberry32(1018);
  const gauss = () => (random() + random() + random() + random() - 2) / 2;

  // Blue mass on the left, red on the right, a violet seam where they meet.
  const clouds: { x: number; y: number; sx: number; sy: number; n: number; color: RGB }[] = [
    { x: 0.44, y: 0.46, sx: 0.2, sy: 0.3, n: 70, color: BLUE },
    { x: 0.56, y: 0.42, sx: 0.08, sy: 0.24, n: 22, color: VIOLET },
    { x: 0.7, y: 0.4, sx: 0.17, sy: 0.28, n: 60, color: RED }
  ];

  // Soft ambient haze first, so the particles sit in light rather than on black.
  for (const c of clouds) {
    const cx = c.x * w;
    const cy = c.y * h;
    const r = Math.max(c.sx * w, c.sy * h) * 1.6;
    const haze = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
    haze.addColorStop(0, rgba(c.color, 0.12));
    haze.addColorStop(1, rgba(c.color, 0));
    ctx.fillStyle = haze;
    ctx.fillRect(cx - r, cy - r, r * 2, r * 2);
  }

  const nodes: { x: number; y: number; c: RGB; hub: boolean }[] = [];
  for (const c of clouds) {
    for (let i = 0; i < c.n; i++) nodes.push({ x: (c.x + gauss() * c.sx) * w, y: (c.y + gauss() * c.sy) * h, c: c.color, hub: random() < 0.1 });
  }

  // Links: short gently curved threads between nearby nodes; hubs reach further, across colours.
  const reach = Math.min(w, h) * 0.22;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      const d = Math.hypot(a.x - b.x, a.y - b.y);
      const limit = a.hub || b.hub ? reach * 1.6 : reach;
      if (d > limit || random() > (a.hub || b.hub ? 0.5 : 0.28)) continue;
      const fade = 1 - d / limit;
      const grad = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
      grad.addColorStop(0, rgba(a.c, 0.32 * fade));
      grad.addColorStop(1, rgba(b.c, 0.32 * fade));
      ctx.strokeStyle = grad;
      ctx.lineWidth = a.hub || b.hub ? 0.9 : 0.6;
      const bend = (random() - 0.5) * d * 0.25;
      const mx = (a.x + b.x) / 2 + ((b.y - a.y) / (d || 1)) * bend;
      const my = (a.y + b.y) / 2 - ((b.x - a.x) / (d || 1)) * bend;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.quadraticCurveTo(mx, my, b.x, b.y);
      ctx.stroke();
    }
  }

  // Stipple dust on a 2px grid, like the landing page's dither.
  for (const c of clouds) {
    for (let i = 0; i < c.n * 26; i++) {
      const x = Math.round(((c.x + gauss() * c.sx * 1.35) * w) / 2) * 2;
      const y = Math.round(((c.y + gauss() * c.sy * 1.25) * h) / 2) * 2;
      ctx.fillStyle = rgba(c.color, 0.12 + random() * 0.4);
      ctx.fillRect(x, y, 1.4, 1.4);
    }
  }

  for (const n of nodes) {
    const radius = n.hub ? 9 : 3.4;
    const glow = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, radius);
    glow.addColorStop(0, rgba(n.c, n.hub ? 0.95 : 0.6));
    glow.addColorStop(1, rgba(n.c, 0));
    ctx.fillStyle = glow;
    ctx.fillRect(n.x - radius, n.y - radius, radius * 2, radius * 2);
    ctx.fillStyle = `rgba(255,255,255,${n.hub ? 0.95 : 0.45})`;
    const core = n.hub ? 1.8 : 1.1;
    ctx.fillRect(n.x - core / 2, n.y - core / 2, core, core);
  }
}

export default function NetworkBackdrop({ className = "" }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return undefined;
    let frame = 0;
    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => draw(canvas));
    });
    observer.observe(canvas);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, []);

  return <canvas ref={ref} aria-hidden="true" className={`pointer-events-none block h-full w-full ${className}`} />;
}
