// The live scene the hero dithers: a rotating particle globe of correlated evidence, threads to the file,
// device, event and finding hubs, evidence streaming into the core, and a pulsing contradiction alert.
// Everything is synthetic and procedural; DitherVeil turns it into the stippled look.
import type { DitherScene } from "../effects/DitherVeil";
import { CORE, GLOBE, HUBS, SIGNAL_DOTS, THREADS, type Point, type Tone } from "./evidenceLayout";

type RGB = [number, number, number];

const BLUE: RGB = [52, 132, 255];
const BLUE_HOT: RGB = [150, 205, 255];
const RED: RGB = [255, 38, 64];
const RED_HOT: RGB = [255, 150, 160];

const toneColor = (tone: Tone, hot = false) => (tone === "alert" ? (hot ? RED_HOT : RED) : hot ? BLUE_HOT : BLUE);

const mulberry32 = (seed: number) => () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const gaussian = (random: () => number) => {
  const u = Math.max(random(), 1e-6);
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * random());
};

const rgba = ([r, g, b]: RGB, a: number) => `rgba(${r},${g},${b},${a})`;

const mixRgb = (a: RGB, b: RGB, k: number): RGB => [
  Math.round(a[0] + (b[0] - a[0]) * k),
  Math.round(a[1] + (b[1] - a[1]) * k),
  Math.round(a[2] + (b[2] - a[2]) * k)
];

/** Groups thousands of dots by colour and alpha so each frame issues a handful of fills, not thousands. */
class DotBatch {
  private buckets = new Map<string, number[]>();

  add(style: string, x: number, y: number, size: number) {
    let list = this.buckets.get(style);
    if (!list) this.buckets.set(style, (list = []));
    list.push(x, y, size);
  }

  flush(ctx: CanvasRenderingContext2D) {
    for (const [style, list] of this.buckets) {
      ctx.fillStyle = style;
      ctx.beginPath();
      for (let i = 0; i < list.length; i += 3) ctx.rect(list[i] - list[i + 2] / 2, list[i + 1] - list[i + 2] / 2, list[i + 2], list[i + 2]);
      ctx.fill();
      list.length = 0;
    }
  }
}

// Five alpha steps per hue keep the bucket count small while still giving depth.
const ALPHA_STEPS = [0.22, 0.4, 0.6, 0.8, 1];
const PALETTE = [BLUE, mixRgb(BLUE, BLUE_HOT, 0.6), mixRgb(BLUE, RED, 0.5), RED, mixRgb(RED, RED_HOT, 0.5)];
const STYLES = PALETTE.map(color => ALPHA_STEPS.map(a => rgba(color, a)));
const styleFor = (hue: number, alpha: number) =>
  STYLES[hue][Math.min(ALPHA_STEPS.length - 1, Math.max(0, Math.round(alpha * (ALPHA_STEPS.length - 1))))];

// Hue indexes into PALETTE.
const HUE_BLUE = 0;
const HUE_BLUE_HOT = 1;
const HUE_VIOLET = 2;
const HUE_RED = 3;
const HUE_RED_HOT = 4;

type GlobeDot = { x: number; y: number; z: number; land: boolean; jitter: number; size: number };
type Mote = { x: number; y: number; hue: number; alpha: number; size: number; phase: number; speed: number };
type Spray = { x: number; y: number; sx: number; sy: number; count: number; tone: Tone | "mixed" };

const SPRAYS: Spray[] = [
  // File card: dense blue spill along its right edge and top.
  { x: 0.245, y: 0.3, sx: 0.035, sy: 0.15, count: 900, tone: "trace" },
  { x: 0.17, y: 0.07, sx: 0.07, sy: 0.025, count: 320, tone: "trace" },
  { x: 0.29, y: 0.2, sx: 0.025, sy: 0.04, count: 260, tone: "trace" },
  // Device card: blue along its left edge and top corner.
  { x: 0.62, y: 0.24, sx: 0.03, sy: 0.08, count: 420, tone: "trace" },
  { x: 0.87, y: 0.07, sx: 0.06, sy: 0.03, count: 320, tone: "trace" },
  // Event card: blue spill on its upper right.
  { x: 0.245, y: 0.66, sx: 0.04, sy: 0.07, count: 700, tone: "trace" },
  { x: 0.3, y: 0.79, sx: 0.02, sy: 0.08, count: 260, tone: "trace" },
  // Finding card: red bloom around the alert hub and the far corner.
  { x: 0.64, y: 0.64, sx: 0.04, sy: 0.045, count: 600, tone: "alert" },
  { x: 0.9, y: 0.93, sx: 0.05, sy: 0.025, count: 380, tone: "alert" },
  { x: 0.56, y: 0.6, sx: 0.04, sy: 0.05, count: 380, tone: "mixed" },
  // Between core and device: the red/blue tangle in the reference.
  { x: 0.53, y: 0.38, sx: 0.045, sy: 0.05, count: 420, tone: "mixed" }
];

const buildGlobe = (random: () => number): GlobeDot[] => {
  const dots: GlobeDot[] = [];
  const count = 5600;
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = golden * i;
    const x = Math.cos(theta) * r;
    const z = Math.sin(theta) * r;
    // Smooth pseudo-continents: dense "land" patches, sparse "ocean".
    const land =
      Math.sin(2.3 * x + 1.1) + 0.8 * Math.sin(2.9 * y + 2.1) + 0.7 * Math.sin(3.7 * z + 0.3) + 0.4 * Math.sin(5.1 * (x + y) + 1.7);
    const isLand = land > 0.45;
    if (!isLand && random() > 0.24) continue;
    dots.push({ x, y, z, land: isLand, jitter: random(), size: isLand ? (random() < 0.2 ? 3 : 2.4) : 1.9 });
  }
  return dots;
};

const buildSprays = (random: () => number): Mote[] => {
  const motes: Mote[] = [];
  for (const spray of SPRAYS) {
    for (let i = 0; i < spray.count; i++) {
      const gx = gaussian(random);
      const gy = gaussian(random);
      const falloff = Math.exp(-(gx * gx + gy * gy) / 3);
      const hue =
        spray.tone === "alert"
          ? random() < 0.25 ? HUE_RED_HOT : HUE_RED
          : spray.tone === "trace"
            ? random() < 0.3 ? HUE_BLUE_HOT : random() < 0.06 ? HUE_RED : HUE_BLUE
            : random() < 0.5 ? HUE_RED : random() < 0.5 ? HUE_BLUE : HUE_VIOLET;
      motes.push({
        x: spray.x + gx * spray.sx,
        y: spray.y + gy * spray.sy,
        hue,
        alpha: 0.5 + 0.5 * falloff * random(),
        size: random() < 0.2 ? 3 : 2.2,
        phase: random() * Math.PI * 2,
        speed: 0.6 + random() * 2.2
      });
    }
  }
  return motes;
};

const buildField = (random: () => number): Mote[] => {
  const motes: Mote[] = [];
  for (let i = 0; i < 1100; i++) {
    const x = random() * 1.04 - 0.02;
    const y = random() * 1.04 - 0.02;
    // Weight the dust toward the globe so the field thins out at the edges like the reference.
    const d = Math.hypot((x - GLOBE.x) * 1.4, y - GLOBE.y);
    if (random() > Math.exp(-d * 2.4) + 0.08) continue;
    const redBias = Math.min(1, Math.max(0, (x - 0.3) * 1.4 + (y - 0.4) * 0.6));
    motes.push({
      x,
      y,
      hue: random() < redBias * 0.7 ? HUE_RED : random() < 0.2 ? HUE_BLUE_HOT : HUE_BLUE,
      alpha: 0.3 + random() * 0.6,
      size: random() < 0.12 ? 2.6 : 2,
      phase: random() * Math.PI * 2,
      speed: 0.4 + random() * 1.6
    });
  }
  return motes;
};

const glowLine = (ctx: CanvasRenderingContext2D, a: Point, b: Point, w: number, h: number, color: RGB, strength: number) => {
  ctx.beginPath();
  ctx.moveTo(a.x * w, a.y * h);
  ctx.lineTo(b.x * w, b.y * h);
  ctx.strokeStyle = rgba(color, 0.08 * strength);
  ctx.lineWidth = 7;
  ctx.stroke();
  ctx.strokeStyle = rgba(color, 0.3 * strength);
  ctx.lineWidth = 2.4;
  ctx.stroke();
  ctx.strokeStyle = rgba(mixRgb(color, [255, 255, 255], 0.35), 0.9 * strength);
  ctx.lineWidth = 1;
  ctx.stroke();
};

const radialGlow = (ctx: CanvasRenderingContext2D, x: number, y: number, radius: number, color: RGB, alpha: number) => {
  const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius);
  gradient.addColorStop(0, rgba(color, alpha));
  gradient.addColorStop(0.45, rgba(color, alpha * 0.35));
  gradient.addColorStop(1, rgba(color, 0));
  ctx.fillStyle = gradient;
  ctx.fillRect(x - radius, y - radius, radius * 2, radius * 2);
};

export function createEvidenceScene(): DitherScene {
  const random = mulberry32(20261018);
  const globe = buildGlobe(random);
  const sprays = buildSprays(random);
  const field = buildField(random);
  const streamSeeds = Array.from({ length: 34 }, () => ({ offset: random(), lane: gaussian(random) }));
  const batch = new DotBatch();
  const tilt = 0.38;
  const cosTilt = Math.cos(tilt);
  const sinTilt = Math.sin(tilt);

  return (ctx, w, h, t) => {
    ctx.globalCompositeOperation = "source-over";
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    ctx.globalCompositeOperation = "lighter";

    const gx = GLOBE.x * w;
    const gy = GLOBE.y * h;
    const radius = GLOBE.radius * w;

    // Atmosphere: blue on the upper left, red on the lower right.
    radialGlow(ctx, gx - radius * 0.35, gy - radius * 0.2, radius * 1.5, BLUE, 0.22);
    radialGlow(ctx, gx + radius * 0.45, gy + radius * 0.3, radius * 1.4, RED, 0.2);

    // Ambient field.
    for (const m of field) {
      const flicker = 0.55 + 0.45 * Math.sin(t * m.speed + m.phase);
      batch.add(styleFor(m.hue, m.alpha * flicker), m.x * w + Math.sin(t * 0.3 + m.phase) * 2, m.y * h, m.size);
    }

    // Particle globe.
    const spin = t * 0.11;
    const cosSpin = Math.cos(spin);
    const sinSpin = Math.sin(spin);
    for (const d of globe) {
      const x1 = d.x * cosSpin + d.z * sinSpin;
      const z1 = -d.x * sinSpin + d.z * cosSpin;
      const y2 = d.y * cosTilt - z1 * sinTilt;
      const z2 = d.y * sinTilt + z1 * cosTilt;
      const front = (z2 + 1) / 2;
      if (!d.land && z2 < -0.2) continue;
      const sx = gx + x1 * radius;
      const sy = gy + y2 * radius;
      const redness = 0.5 + x1 * 0.5 + y2 * 0.22 + (d.jitter - 0.5) * 0.7;
      const hue =
        redness > 0.72 ? (d.jitter > 0.8 ? HUE_RED_HOT : HUE_RED) : redness > 0.52 ? HUE_VIOLET : d.jitter > 0.75 ? HUE_BLUE_HOT : HUE_BLUE;
      const alpha = (d.land ? 0.42 : 0.18) + front * (d.land ? 0.58 : 0.4);
      batch.add(styleFor(hue, alpha), sx, sy, d.size * (0.75 + front * 0.35));
    }

    // Rim particles that hug the silhouette and drift.
    for (let i = 0; i < 520; i++) {
      const angle = (i / 520) * Math.PI * 2 + t * 0.05 + Math.sin(i * 12.9898) * 0.02;
      const spread = 1 + Math.abs(Math.sin(i * 78.233 + t * 0.4)) * 0.09;
      const redSide = Math.cos(angle) > 0.15 || Math.sin(angle) > 0.6;
      batch.add(
        styleFor(redSide ? HUE_RED : HUE_BLUE_HOT, 0.35 + 0.4 * Math.abs(Math.sin(i * 3.1 + t))),
        gx + Math.cos(angle) * radius * spread,
        gy + Math.sin(angle) * radius * spread,
        2.2
      );
    }

    // Card sprays.
    for (const m of sprays) {
      const flicker = 0.55 + 0.45 * Math.sin(t * m.speed + m.phase);
      batch.add(
        styleFor(m.hue, m.alpha * flicker),
        m.x * w + Math.sin(t * 0.5 + m.phase) * 1.5,
        m.y * h + Math.cos(t * 0.4 + m.phase) * 1.5,
        m.size
      );
    }

    // Faint outer threads and signal dots.
    for (const [a, b] of THREADS) glowLine(ctx, a, b, w, h, RED, 0.28);
    for (const [i, dot] of SIGNAL_DOTS.entries()) {
      const pulse = 0.6 + 0.4 * Math.sin(t * 1.7 + i * 1.3);
      radialGlow(ctx, dot.x * w, dot.y * h, 9, RED, 0.7 * pulse);
      batch.add(styleFor(HUE_RED_HOT, pulse), dot.x * w, dot.y * h, 2.6);
    }

    // Hub threads with evidence streaming into the core; the finding stream flows out of it.
    for (const [name, hub] of Object.entries(HUBS)) {
      const color = toneColor(hub.tone);
      glowLine(ctx, CORE, hub, w, h, color, 1);
      radialGlow(ctx, hub.x * w, hub.y * h, w * 0.05, color, 0.45);
      const outward = name === "finding";
      const dx = (hub.x - CORE.x) * w;
      const dy = (hub.y - CORE.y) * h;
      const length = Math.hypot(dx, dy) || 1;
      const nx = -dy / length;
      const ny = dx / length;
      for (const seed of streamSeeds) {
        const p = (seed.offset + t * 0.16) % 1;
        const k = outward ? p : 1 - p;
        const lane = seed.lane * 3.2 * Math.sin(Math.PI * k);
        batch.add(
          styleFor(hub.tone === "alert" ? HUE_RED_HOT : HUE_BLUE_HOT, 0.5 + 0.5 * Math.sin(Math.PI * k)),
          CORE.x * w + dx * k + nx * lane,
          CORE.y * h + dy * k + ny * lane,
          2.6
        );
      }
    }

    batch.flush(ctx);

    // Core: the evidence everything resolves to.
    const corePulse = 0.8 + 0.2 * Math.sin(t * 2.1);
    radialGlow(ctx, CORE.x * w, CORE.y * h, w * 0.09, BLUE, 0.55 * corePulse);
    radialGlow(ctx, CORE.x * w + w * 0.02, CORE.y * h, w * 0.07, RED, 0.35 * corePulse);

    // Contradiction alert: two staggered rings expanding from the finding hub.
    for (let i = 0; i < 2; i++) {
      const phase = ((t + i * 1.2) % 2.4) / 2.4;
      ctx.beginPath();
      ctx.arc(HUBS.finding.x * w, HUBS.finding.y * h, w * (0.03 + phase * 0.075), 0, Math.PI * 2);
      ctx.strokeStyle = rgba(RED, 0.75 * (1 - phase));
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    ctx.globalCompositeOperation = "source-over";
  };
}
