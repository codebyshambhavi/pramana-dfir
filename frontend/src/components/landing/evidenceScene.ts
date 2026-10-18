// The live scene the hero dithers: a fluid particle cloud of correlated evidence, threads to the file,
// device, event and finding hubs, evidence streaming into the core, and a pulsing contradiction alert.
// Everything is synthetic and procedural; DitherVeil turns it into the stippled look.
import type { DitherScene } from "../effects/DitherVeil";
import { CORE, GLOBE, HUBS, SIGNAL_DOTS, THREADS, type Point, type Tone } from "./evidenceLayout";

type RGB = [number, number, number];

const BLUE: RGB = [52, 132, 255];
const BLUE_HOT: RGB = [150, 205, 255];
const RED: RGB = [255, 38, 64];
const RED_HOT: RGB = [255, 150, 160];
const WHITE: RGB = [236, 241, 255];

const toneColor = (tone: Tone) => (tone === "alert" ? RED : BLUE);

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
const PALETTE = [BLUE, mixRgb(BLUE, BLUE_HOT, 0.6), mixRgb(BLUE, RED, 0.5), RED, mixRgb(RED, RED_HOT, 0.5), WHITE];
const STYLES = PALETTE.map(color => ALPHA_STEPS.map(a => rgba(color, a)));
const styleFor = (hue: number, alpha: number) =>
  STYLES[hue][Math.min(ALPHA_STEPS.length - 1, Math.max(0, Math.round(alpha * (ALPHA_STEPS.length - 1))))];

// Hue indexes into PALETTE.
const HUE_BLUE = 0;
const HUE_BLUE_HOT = 1;
const HUE_VIOLET = 2;
const HUE_RED = 3;
const HUE_RED_HOT = 4;
const HUE_WHITE = 5;

/** A particle of the evidence cloud, in polar terms around the cloud's centre. */
type CloudDot = { angle: number; depth: number; spin: number; phase: number; jitter: number; size: number };
/** A particle shed from the cloud's edge that drifts outward and fades. */
type Wisp = { angle: number; offset: number; speed: number; drift: number; jitter: number };
type Mote = { x: number; y: number; hue: number; alpha: number; size: number; phase: number; speed: number };
type Spray = { x: number; y: number; sx: number; sy: number; count: number; tone: Tone };

const SPRAYS: Spray[] = [
  // File card: blue spill along its right edge and top.
  { x: 0.245, y: 0.3, sx: 0.03, sy: 0.14, count: 480, tone: "trace" },
  { x: 0.17, y: 0.07, sx: 0.07, sy: 0.025, count: 220, tone: "trace" },
  // Device card: blue along its left edge and top corner.
  { x: 0.615, y: 0.22, sx: 0.025, sy: 0.07, count: 280, tone: "trace" },
  { x: 0.87, y: 0.07, sx: 0.06, sy: 0.03, count: 240, tone: "trace" },
  // Event card: blue spill on its upper right.
  { x: 0.245, y: 0.66, sx: 0.035, sy: 0.07, count: 480, tone: "trace" },
  // Finding card: a red bloom around the alert hub and the far corner, kept off the card's text.
  { x: HUBS.finding.x - 0.01, y: HUBS.finding.y, sx: 0.03, sy: 0.04, count: 420, tone: "alert" },
  { x: 0.93, y: 0.95, sx: 0.04, sy: 0.02, count: 220, tone: "alert" }
];

const buildCloud = (random: () => number): CloudDot[] =>
  Array.from({ length: 3000 }, () => {
    // Bias toward the edge so the silhouette reads, with a thinner, softer interior.
    const depth = Math.pow(random(), 0.3);
    return {
      angle: random() * Math.PI * 2,
      depth,
      // Inner particles swirl faster than the rim, which keeps the mass flowing rather than spinning rigidly.
      spin: (0.05 + 0.16 * (1 - depth)) * (random() < 0.8 ? 1 : -0.6),
      phase: random() * Math.PI * 2,
      jitter: random(),
      size: random() < 0.15 ? 2.4 : 1.9
    };
  });

const buildWisps = (random: () => number): Wisp[] =>
  Array.from({ length: 480 }, () => ({
    angle: random() * Math.PI * 2,
    offset: random(),
    speed: 0.08 + random() * 0.14,
    drift: (random() - 0.5) * 0.5,
    jitter: random()
  }));

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
          : random() < 0.3 ? HUE_BLUE_HOT : random() < 0.05 ? HUE_RED : HUE_BLUE;
      motes.push({
        x: spray.x + gx * spray.sx,
        y: spray.y + gy * spray.sy,
        hue,
        alpha: 0.45 + 0.5 * falloff * random(),
        size: random() < 0.2 ? 2.8 : 2.2,
        phase: random() * Math.PI * 2,
        speed: 0.6 + random() * 2.2
      });
    }
  }
  return motes;
};

const buildField = (random: () => number): Mote[] => {
  const motes: Mote[] = [];
  for (let i = 0; i < 900; i++) {
    const x = random() * 1.04 - 0.02;
    const y = random() * 1.04 - 0.02;
    // Weight the dust toward the cloud so the field thins out at the edges like the reference.
    const d = Math.hypot((x - GLOBE.x) * 1.4, y - GLOBE.y);
    if (random() > Math.exp(-d * 2.6) + 0.06) continue;
    const redBias = Math.min(1, Math.max(0, (x - 0.3) * 1.4 + (y - 0.4) * 0.6));
    motes.push({
      x,
      y,
      hue: random() < redBias * 0.7 ? HUE_RED : random() < 0.2 ? HUE_BLUE_HOT : HUE_BLUE,
      alpha: 0.25 + random() * 0.55,
      size: random() < 0.12 ? 2.6 : 2,
      phase: random() * Math.PI * 2,
      speed: 0.4 + random() * 1.6
    });
  }
  return motes;
};

/** Edge of the cloud at a given angle and time: a few slow, out-of-phase waves make it breathe and flow. */
const boundary = (angle: number, t: number) =>
  1 +
  0.11 * Math.sin(2 * angle + t * 0.33) +
  0.06 * Math.sin(3 * angle - t * 0.47 + 1.3) +
  0.035 * Math.sin(5 * angle + t * 0.71 + 0.4);

/** Colour by where a particle sits: blue upper left, red lower right, white where they meet on the rim. */
const cloudHue = (cos: number, sin: number, depth: number, jitter: number) => {
  const side = cos * 0.75 + sin * 0.55 + (jitter - 0.5) * 0.55;
  if (side > 0.28) return jitter > 0.82 ? HUE_RED_HOT : HUE_RED;
  if (side < -0.28) return jitter > 0.78 ? HUE_BLUE_HOT : HUE_BLUE;
  return depth > 0.85 && jitter > 0.45 ? HUE_WHITE : HUE_VIOLET;
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
  const cloud = buildCloud(random);
  const wisps = buildWisps(random);
  const sprays = buildSprays(random);
  const field = buildField(random);
  const streamSeeds = Array.from({ length: 30 }, () => ({ offset: random(), lane: gaussian(random) }));
  const batch = new DotBatch();

  return (ctx, w, h, t) => {
    ctx.globalCompositeOperation = "source-over";
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    ctx.globalCompositeOperation = "lighter";

    const gx = GLOBE.x * w;
    const gy = GLOBE.y * h;
    const radius = GLOBE.radius * w;

    // Atmosphere: blue on the upper left, red on the lower right, drifting slowly.
    radialGlow(ctx, gx - radius * (0.35 + 0.08 * Math.sin(t * 0.3)), gy - radius * 0.2, radius * 1.5, BLUE, 0.2);
    radialGlow(ctx, gx + radius * (0.45 + 0.08 * Math.cos(t * 0.27)), gy + radius * 0.3, radius * 1.4, RED, 0.18);

    // Ambient field.
    for (const m of field) {
      const flicker = 0.55 + 0.45 * Math.sin(t * m.speed + m.phase);
      batch.add(styleFor(m.hue, m.alpha * flicker), m.x * w + Math.sin(t * 0.3 + m.phase) * 2, m.y * h, m.size);
    }

    // Evidence cloud: particles swirl inside a breathing, wave-edged silhouette and get pushed by a gentle
    // flow field. Rim particles carry a red/blue ghost on either side for a slight chromatic split.
    for (const d of cloud) {
      const angle = d.angle + d.spin * t;
      const cos = Math.cos(angle);
      const sin = Math.sin(angle);
      const r = radius * (d.depth * boundary(angle, t) + 0.025 * Math.sin(t * 0.8 + d.phase));
      let x = cos * r;
      let y = sin * r * 0.94;
      x += radius * 0.06 * Math.sin((y / radius) * 2.6 + t * 0.55);
      y += radius * 0.06 * Math.cos((x / radius) * 2.3 - t * 0.45);
      const hue = cloudHue(cos, sin, d.depth, d.jitter);
      const rim = Math.pow(d.depth, 4);
      const alpha = 0.16 + 0.8 * rim + 0.1 * Math.sin(t * 1.3 + d.phase);
      const px = gx + x;
      const py = gy + y;
      batch.add(styleFor(hue, alpha), px, py, d.size);
      if (d.depth > 0.86) {
        const split = 1.6;
        batch.add(styleFor(HUE_RED, alpha * 0.45), px + cos * split, py + sin * split, d.size * 0.9);
        batch.add(styleFor(HUE_BLUE_HOT, alpha * 0.45), px - cos * split, py - sin * split, d.size * 0.9);
      }
    }

    // Wisps shed from the edge: they trail off the silhouette so it reads as fluid rather than a hard ball.
    for (const s of wisps) {
      const life = (s.offset + t * s.speed) % 1;
      const angle = s.angle + s.drift * life + 0.05 * t;
      const reach = radius * boundary(angle, t) * (1 + life * 0.42);
      const cos = Math.cos(angle);
      const sin = Math.sin(angle);
      const fade = Math.sin(Math.PI * life) * (1 - life * 0.5);
      batch.add(
        styleFor(cloudHue(cos, sin, 1, s.jitter), 0.85 * fade),
        gx + cos * reach,
        gy + sin * reach * 0.94,
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
    for (const [a, b] of THREADS) glowLine(ctx, a, b, w, h, RED, 0.24);
    for (const [i, dot] of SIGNAL_DOTS.entries()) {
      const pulse = 0.6 + 0.4 * Math.sin(t * 1.7 + i * 1.3);
      radialGlow(ctx, dot.x * w, dot.y * h, 9, RED, 0.6 * pulse);
      batch.add(styleFor(HUE_RED_HOT, pulse), dot.x * w, dot.y * h, 2.6);
    }

    // Hub threads with evidence streaming into the core; the finding stream flows out of it.
    for (const [name, hub] of Object.entries(HUBS)) {
      const color = toneColor(hub.tone);
      glowLine(ctx, CORE, hub, w, h, color, 1);
      radialGlow(ctx, hub.x * w, hub.y * h, w * 0.045, color, 0.4);
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
    radialGlow(ctx, CORE.x * w, CORE.y * h, w * 0.085, BLUE, 0.5 * corePulse);
    radialGlow(ctx, CORE.x * w + w * 0.02, CORE.y * h, w * 0.065, RED, 0.32 * corePulse);

    // Contradiction alert: two staggered rings expanding from the finding hub.
    for (let i = 0; i < 2; i++) {
      const phase = ((t + i * 1.2) % 2.4) / 2.4;
      ctx.beginPath();
      ctx.arc(HUBS.finding.x * w, HUBS.finding.y * h, w * (0.03 + phase * 0.065), 0, Math.PI * 2);
      ctx.strokeStyle = rgba(RED, 0.7 * (1 - phase));
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    ctx.globalCompositeOperation = "source-over";
  };
}
