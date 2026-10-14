// Clean benchmark fixture: harmless constants and a secret read from the environment (P12-5a).
const apiKeyHeaderName = "x-api-key"; // short, not a secret
const token = process.env.EXAMPLE_API_TOKEN; // read at start-up, no literal

export function buildExampleHeaders() {
  return { [apiKeyHeaderName]: token ?? "" };
}
