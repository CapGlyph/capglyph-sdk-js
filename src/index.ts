/**
 * @capglyph/sdk — TypeScript SDK for CapGlyph (Local WASM + API)
 * Spec: capglyph-spec v1.0.0 · Core: capglyph-core 0.1.0
 *
 * Two-type design:
 *   Local SDK (WASM/FFI from Rust Core) — src/local.ts, src/framing.ts
 *   API SDK (typed HTTP client for capglyphd) — src/client.ts
 *
 * Verification: conformance vectors (1024/1024) via src/conformance.ts
 */

export * from "./types.js";
export * from "./framing.js";
export * from "./conformance.js";
export * from "./client.js";
export * from "./local.js";

// Re-export convenient singletons
export { local as defaultLocal, LocalClient } from "./local.js";
export { CapglyphClient, CapglyphApiError } from "./client.js";
export {
  seal,
  open,
  validateFrame,
  cborEncode,
  cborDecode,
  cborValidate,
  hmacTag,
  hmacVerify,
} from "./framing.js";
export {
  validateVector,
  validateVectors,
  findVectorsRoot,
  loadVectors,
} from "./conformance.js";
