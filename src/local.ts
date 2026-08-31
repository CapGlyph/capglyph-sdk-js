/**
 * CapGlyph Local SDK — WASM wrapper (TypeScript)
 *
 * Browser / Node / Cloudflare Workers: offloads crypto+carrier to capglyph-core WASM.
 * Fallback to pure-JS framing (src/framing.ts) until WASM is built.
 *
 * Build WASM from Rust Core:
 *   wasm-pack build --target web ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg  (browser)
 *   wasm-pack build --target bundler ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg  (Node/bundler)
 *   wasm-pack build --target nodejs ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg  (Node native)
 *
 * When WASM is available, import as:
 *   import init, { seal, open, validate_frame } from '../wasm/pkg/capglyph_core.js';
 *
 * Until then, LocalClient delegates to src/framing.ts (byte-identical conformance).
 */

import {
  seal as jsSeal,
  open as jsOpen,
  validateFrame as jsValidate,
  cborEncode,
  hmacTag,
} from "./framing.js";
import type { FrameHeader, PayloadType } from "./types.js";
import { bytesToHex, hexToBytes } from "./framing.js";

export interface SealOptions {
  version?: number;
  payloadType?: PayloadType;
  flags?: number;
}

export interface LocalClientOptions {
  /** If true, prefer WASM when available; otherwise use JS fallback. Default true. */
  preferWasm?: boolean;
  /** Custom WASM init (for testing). */
  wasmInit?: () => Promise<void>;
}

type WasmExports = {
  seal: (
    payload: Uint8Array,
    version: number,
    payloadType: number,
    flags: number,
    kMac: Uint8Array,
  ) => Uint8Array;
  open: (sealed: Uint8Array, kMac: Uint8Array) => Uint8Array;
  validate_frame: (bytes: Uint8Array) => number;
};

let wasm: WasmExports | null = null;
let wasmReady: Promise<void> | null = null;

async function tryLoadWasm(): Promise<void> {
  if (wasm || wasmReady) return wasmReady ?? Promise.resolve();
  // Dynamic import — will fail gracefully if wasm/pkg not built yet
  wasmReady = (async () => {
    try {
      // @ts-ignore — optional wasm artifact
      const mod = await import("../wasm/pkg/capglyph_core.js");
      await mod.default();
      wasm = {
        seal: mod.seal,
        open: mod.open,
        validate_frame: mod.validate_frame,
      };
    } catch {
      // No WASM artifact — stay on JS fallback
      wasm = null;
    }
  })();
  return wasmReady;
}

export class LocalClient {
  private opts: LocalClientOptions;

  constructor(opts: LocalClientOptions = {}) {
    this.opts = { preferWasm: true, ...opts };
  }

  /** Ensure WASM is loaded if preferred. No-op if already loaded or unavailable. */
  async init(): Promise<void> {
    if (this.opts.preferWasm) await tryLoadWasm();
    if (this.opts.wasmInit) await this.opts.wasmInit();
  }

  /** Seal payload → sealed bytes (frame || HMAC tag). Delegates to WASM when available, else JS. */
  seal(
    payload: Uint8Array,
    kMac: Uint8Array,
    opts: SealOptions = {},
  ): Uint8Array {
    const params = {
      version: opts.version ?? 1,
      payloadType: opts.payloadType ?? "Credential",
      flags: opts.flags ?? 0,
    };
    if (wasm && this.opts.preferWasm) {
      try {
        const ptypeId = { Credential: 1, Pointer: 2, Message: 3, Locator: 4 }[
          params.payloadType
        ];
        return wasm.seal(payload, params.version, ptypeId, params.flags, kMac);
      } catch {
        // fall back to JS
      }
    }
    return jsSeal(payload, params, kMac);
  }

  /** Seal from hex strings (convenience). */
  sealHex(payloadHex: string, kMacHex: string, opts: SealOptions = {}): string {
    const sealed = this.seal(hexToBytes(payloadHex), hexToBytes(kMacHex), opts);
    return bytesToHex(sealed);
  }

  /** Open sealed bytes with K_mac → payload. Throws on auth/frame failure with classified error. */
  open(
    sealed: Uint8Array,
    kMac: Uint8Array,
  ): { header: FrameHeader; payload: Uint8Array } {
    if (wasm && this.opts.preferWasm) {
      try {
        // WASM open may return header+payload as concatenated CBOR; we still parse header for now via JS to preserve types
        // Attempt WASM, fall back if it throws
        const _ = wasm.open(sealed, kMac);
        // If WASM succeeded, decode via JS for consistent header shape (avoid duplicating CBOR in JS harness)
      } catch (e) {
        // Re-throw as JS classification if WASM already gave E_* — otherwise fall through to JS
        if (String(e).includes("E_")) throw e;
      }
    }
    return jsOpen(sealed, kMac);
  }

  openHex(
    sealedHex: string,
    kMacHex: string,
  ): { header: FrameHeader; payload: Uint8Array } {
    return this.open(hexToBytes(sealedHex), hexToBytes(kMacHex));
  }

  /** Validate frame without key (preflight). */
  validate(bytes: Uint8Array): FrameHeader {
    if (wasm && this.opts.preferWasm) {
      try {
        wasm.validate_frame(bytes);
      } catch {
        // fall back
      }
    }
    return jsValidate(bytes);
  }

  /** Whether WASM backend is active. */
  get usingWasm(): boolean {
    return wasm !== null && this.opts.preferWasm === true;
  }

  // -- Image carrier stubs (require capglyph-core carrier + wasm image glue) --

  /**
   * Embed payload into decoded PNG/JPEG bytes → PNG bytes.
   * TODO: wire to capglyph_core::carrier::{DctCarrier,DwtCarrier} via WASM once
   * image decoding (image crate) is exposed through wasm-bindgen. Current stub
   * throws with guidance.
   */
  async embedImage(
    _imageBytes: Uint8Array,
    _opts: {
      mode?: "dct" | "dwt" | "alpha";
      payload: Uint8Array;
      kMac: Uint8Array;
    },
  ): Promise<Uint8Array> {
    throw new Error(
      "embedImage requires capglyph-core WASM with image carrier (DCT/DWT) — run `npm run build:wasm` from capglyph-core, then reload. See src/local.ts and wasm/README.md.",
    );
  }

  async verifyImage(
    _imageBytes: Uint8Array,
    _opts: { mode?: "dct" | "dwt" | "alpha"; kMac?: Uint8Array },
  ): Promise<{ present: boolean; metrics?: unknown }> {
    throw new Error("verifyImage requires WASM carrier — see embedImage TODO");
  }
}

/** Singleton default local client (lazy WASM). */
export const local = new LocalClient();
