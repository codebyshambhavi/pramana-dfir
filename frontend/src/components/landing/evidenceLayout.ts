// Shared geometry for the hero evidence network. Positions are fractions of the visual's width and height,
// so the dithered canvas scene and the HTML cards drawn over it stay aligned at every size.
export const VISUAL_ASPECT = 886 / 580;

export type Point = { x: number; y: number };
export type Tone = "trace" | "alert";

export const CORE: Point = { x: 0.451, y: 0.488 };

export const GLOBE = { x: 0.44, y: 0.515, radius: 0.19 };

export const HUBS: Record<"file" | "device" | "event" | "finding", Point & { tone: Tone }> = {
  file: { x: 0.282, y: 0.19, tone: "trace" },
  device: { x: 0.612, y: 0.3, tone: "trace" },
  event: { x: 0.287, y: 0.676, tone: "trace" },
  finding: { x: 0.612, y: 0.662, tone: "alert" }
};

/** Faint outer threads: the network keeps going past what the hero shows. */
export const THREADS: [Point, Point][] = [
  [CORE, { x: 0.538, y: 0.026 }],
  [{ x: 0.538, y: 0.026 }, { x: 0.76, y: -0.02 }],
  [{ x: 0.538, y: 0.026 }, { x: 0.3, y: -0.03 }],
  [HUBS.device, { x: 0.97, y: 0.0 }],
  [HUBS.finding, { x: 1.02, y: 0.95 }],
  [HUBS.event, { x: 0.36, y: 1.02 }],
  [CORE, { x: 0.86, y: 0.5 }]
];

export const SIGNAL_DOTS: Point[] = [
  { x: 0.538, y: 0.026 },
  { x: 0.79, y: 0.12 },
  { x: 0.935, y: 0.43 },
  { x: 0.72, y: 0.95 },
  { x: 0.4, y: 0.94 },
  { x: 0.33, y: 0.03 },
  { x: 0.985, y: 0.86 }
];
