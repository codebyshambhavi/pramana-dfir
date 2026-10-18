// Role 4: typed client for contracts/openapi.yaml.
// Point VITE_API_URL at a Prism mock first, then at the real backend.
export const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:4010";

export async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`);
  if (!response.ok) throw new Error(`${path} failed with ${response.status}`);
  return response.json() as Promise<T>;
}

// TODO: add one function per endpoint in the OpenAPI spec.
