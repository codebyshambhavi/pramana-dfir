// Role 4 / T11: loads the recorded CASE-DEMO-IST run on first use, as its own chunk, so the ~1.4 MB of recorded JSON
// is fetched only when a T11 view is opened in demo mode, not with every page. The promise is cached.
export type Recording = (typeof import("./case-demo-ist"))["RECORDED_CASE_DEMO_IST"];

let cached: Promise<Recording> | null = null;

export function loadRecording(): Promise<Recording> {
  cached ??= import("./case-demo-ist").then(m => m.RECORDED_CASE_DEMO_IST);
  // A failed load (e.g. a network blip) should not be remembered.
  cached.catch(() => (cached = null));
  return cached;
}
