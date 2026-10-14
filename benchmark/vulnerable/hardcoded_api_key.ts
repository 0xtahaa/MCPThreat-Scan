// Benchmark fixture: Hardcoded Secret in a TypeScript MCP server (P12-5a).
// Simulated value - not a real key.
const apiKey = "demo_key_0123456789abcdef0123456789abcdef01234567"; // VULNERABLE LINE: simulated hardcoded API key.

export function buildExampleHeaders() {
  return { Authorization: `Bearer ${apiKey}`, "Example-Api-Version": "2026-01-01" };
}
