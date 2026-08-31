/**
 * CapGlyph framing — CBOR + HMAC-SHA256 — pure JS implementation
 * Mirrors capglyph_core::framing::{cbor,auth,seal,open} (capglyph-core/src/framing.rs)
 * Spec: capglyph-spec/spec.md §3 canonical CBOR array [version, payload_type, flags, payload_len, payload_bstr] + 32B tag
 *
 * This is the Local SDK's pure-JS fallback. Production Local SDK will delegate to
 * capglyph-core WASM (wasm-pack) via src/local.ts; this module provides the same
 * semantics without WASM for conformance and Node testing.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import type { FrameHeader, PayloadType } from "./types.js";
import { PayloadTypeFromId, PayloadTypeId } from "./types.js";

export type PayloadTypeName = PayloadType;

export interface FramingParams {
  version: number;
  payloadType: PayloadType;
  flags: number;
}

export function defaultParams(): FramingParams {
  return { version: 1, payloadType: "Credential", flags: 0 };
}

// -- CBOR encoding (deterministic, minimal) -------------------------
// CborFrame := [ version:uint, payload_type:uint, flags:uint, payload_len:uint, payload:bstr ]
// Encoded as CBOR array(5) header 0x85, then each uint as major 0, then bstr major 2.

function encodeUint(n: number): Uint8Array {
  if (n <= 23) return Uint8Array.of(n);
  if (n <= 0xff) return Uint8Array.of(0x18, n);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0x19;
    b[1] = (n >>> 8) & 0xff;
    b[2] = n & 0xff;
    return b;
  }
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0x1a;
    b[1] = (n >>> 24) & 0xff;
    b[2] = (n >>> 16) & 0xff;
    b[3] = (n >>> 8) & 0xff;
    b[4] = n & 0xff;
    return b;
  }
  throw new Error(`uint too large ${n}`);
}

function encodeBstr(payload: Uint8Array): Uint8Array {
  const n = payload.length;
  let header: Uint8Array;
  if (n <= 23) header = Uint8Array.of(0x40 + n);
  else if (n <= 0xff) header = Uint8Array.of(0x58, n);
  else if (n <= 0xffff) {
    header = new Uint8Array(3);
    header[0] = 0x59;
    header[1] = (n >>> 8) & 0xff;
    header[2] = n & 0xff;
  } else if (n <= 0xffffffff) {
    header = new Uint8Array(5);
    header[0] = 0x5a;
    header[1] = (n >>> 24) & 0xff;
    header[2] = (n >>> 16) & 0xff;
    header[3] = (n >>> 8) & 0xff;
    header[4] = n & 0xff;
  } else throw new Error("bstr too large");
  const out = new Uint8Array(header.length + n);
  out.set(header, 0);
  out.set(payload, header.length);
  return out;
}

export function cborEncode(
  payload: Uint8Array,
  params: FramingParams,
): Uint8Array {
  const parts: Uint8Array[] = [
    Uint8Array.of(0x85), // array 5
    encodeUint(params.version),
    encodeUint(PayloadTypeId[params.payloadType]),
    encodeUint(params.flags),
    encodeUint(payload.length),
    encodeBstr(payload),
  ];
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// -- CBOR decoding (minimal, matches tools/conformance.py cbor_decode_frame) --

function decodeUintAt(data: Uint8Array, p: { off: number }): number {
  if (p.off >= data.length) throw new Error("truncated uint");
  const b = data[p.off++];
  const mt = b >> 5;
  const ai = b & 0x1f;
  if (mt !== 0) throw new Error(`expected major 0, got ${mt} at ${p.off - 1}`);
  if (ai <= 23) return ai;
  if (ai === 24) {
    if (p.off >= data.length) throw new Error("truncated uint 1");
    return data[p.off++];
  }
  if (ai === 25) {
    if (p.off + 2 > data.length) throw new Error("truncated uint 2");
    const v = (data[p.off] << 8) | data[p.off + 1];
    p.off += 2;
    return v;
  }
  if (ai === 26) {
    if (p.off + 4 > data.length) throw new Error("truncated uint 4");
    const v =
      ((data[p.off] << 24) >>> 0) +
      (data[p.off + 1] << 16) +
      (data[p.off + 2] << 8) +
      data[p.off + 3];
    p.off += 4;
    return v;
  }
  if (ai === 27) {
    if (p.off + 8 > data.length) throw new Error("truncated uint 8");
    // Only support up to 32-bit payload_len in vectors (65535), so reading 64-bit as JS number is safe if < 2^53
    let v = 0;
    for (let i = 0; i < 8; i++) v = v * 256 + data[p.off + i];
    p.off += 8;
    return v;
  }
  throw new Error(`unsupported ai ${ai}`);
}

export function cborDecode(frame: Uint8Array): {
  header: FrameHeader;
  payload: Uint8Array;
} {
  if (frame.length < 1) throw new Error("empty");
  const p = { off: 0 };
  if (frame[p.off++] !== 0x85)
    throw new Error(`expected array 0x85, got ${frame[0]?.toString(16)}`);
  const version = decodeUintAt(frame, p);
  const ptypeId = decodeUintAt(frame, p);
  const flags = decodeUintAt(frame, p);
  const payloadLen = decodeUintAt(frame, p);
  if (p.off >= frame.length) throw new Error("truncated bstr header");
  const hb = frame[p.off++];
  const mt = hb >> 5;
  const ai = hb & 0x1f;
  if (mt !== 2) throw new Error(`expected bstr major 2, got ${mt}`);
  let blen: number;
  if (ai <= 23) blen = ai;
  else if (ai === 24) {
    if (p.off >= frame.length) throw new Error("truncated bstr len 1");
    blen = frame[p.off++];
  } else if (ai === 25) {
    if (p.off + 2 > frame.length) throw new Error("truncated bstr len 2");
    blen = (frame[p.off] << 8) | frame[p.off + 1];
    p.off += 2;
  } else if (ai === 26) {
    if (p.off + 4 > frame.length) throw new Error("truncated bstr len 4");
    blen =
      ((frame[p.off] << 24) >>> 0) +
      (frame[p.off + 1] << 16) +
      (frame[p.off + 2] << 8) +
      frame[p.off + 3];
    p.off += 4;
  } else if (ai === 27) {
    if (p.off + 8 > frame.length) throw new Error("truncated bstr len 8");
    blen = 0;
    for (let i = 0; i < 8; i++) blen = blen * 256 + frame[p.off + i];
    p.off += 8;
  } else throw new Error("indefinite bstr not allowed");
  if (p.off + blen > frame.length) throw new Error("truncated bstr payload");
  const payload = frame.slice(p.off, p.off + blen);
  p.off += blen;
  if (p.off !== frame.length)
    throw new Error(`trailing bytes ${frame.length - p.off}`);
  if (payloadLen !== blen)
    throw new Error(
      `payload_len mismatch header ${payloadLen} vs bstr ${blen}`,
    );
  if (version !== 1) throw new Error(`unsupported version ${version}`);
  const payloadType = PayloadTypeFromId[ptypeId];
  if (!payloadType) throw new Error(`unknown PayloadType ${ptypeId}`);
  const header: FrameHeader = { version, payloadType, flags, payloadLen };
  return { header, payload };
}

export function cborValidate(frame: Uint8Array): FrameHeader {
  const { header } = cborDecode(frame);
  if (header.version !== 1)
    throw new Error(`unsupported version ${header.version}`);
  return header;
}

// -- HMAC ----------------------------------------------------------

export function hmacTag(frame: Uint8Array, kMac: Uint8Array): Uint8Array {
  if (kMac.length !== 32) throw new Error("K_mac must be 32 bytes");
  const mac = createHmac("sha256", kMac);
  mac.update(frame);
  return new Uint8Array(mac.digest());
}

export function hmacVerify(
  frame: Uint8Array,
  tag: Uint8Array,
  kMac: Uint8Array,
): void {
  const expected = hmacTag(frame, kMac);
  if (
    expected.length !== tag.length ||
    !timingSafeEqual(Buffer.from(expected), Buffer.from(tag))
  ) {
    throw new Error("HMAC verification failed");
  }
}

// -- High-level seal/open ------------------------------------------

export function seal(
  payload: Uint8Array,
  params: FramingParams,
  kMac: Uint8Array,
): Uint8Array {
  const frame = cborEncode(payload, params);
  const tag = hmacTag(frame, kMac);
  const out = new Uint8Array(frame.length + 32);
  out.set(frame, 0);
  out.set(tag, frame.length);
  return out;
}

export function open(
  sealed: Uint8Array,
  kMac: Uint8Array,
): { header: FrameHeader; payload: Uint8Array } {
  if (sealed.length < 32) throw new Error("sealed frame too short for tag");
  const frame = sealed.slice(0, sealed.length - 32);
  const tag = sealed.slice(sealed.length - 32);
  hmacVerify(frame, tag, kMac);
  const { header, payload } = cborDecode(frame);
  if (header.version !== 1)
    throw new Error(`unsupported version ${header.version}`);
  return { header, payload };
}

export function validateFrame(bytes: Uint8Array): FrameHeader {
  if (bytes.length >= 32) {
    const framePart = bytes.slice(0, bytes.length - 32);
    try {
      return cborValidate(framePart);
    } catch {
      // fallthrough to try as bare frame
    }
  }
  return cborValidate(bytes);
}

// -- helpers -------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  if (hex === "") return new Uint8Array(0);
  if (hex.length % 2 !== 0) throw new Error("odd hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

// Error classification (mirrors capglyph_core::error::classify_str)
export function classifyError(msg: string): string {
  const m = msg.toLowerCase();
  if (
    m.includes("unsupported version") ||
    m.includes("version_unsupported") ||
    m.includes("e_version_unsupported")
  )
    return "E_VERSION_UNSUPPORTED";
  if (
    m.includes("payload length mismatch") ||
    m.includes("cbor frame decode failed") ||
    m.includes("sealed frame too short") ||
    m.includes("truncated") ||
    m.includes("bstr") ||
    m.includes("unknown payloadtype") ||
    m.includes("payload not bstr") ||
    m.includes("wrong cbor") ||
    m.includes("expected array 0x85") ||
    m.includes("payload_len mismatch")
  )
    return "E_MALFORMED_FRAME";
  if (
    m.includes("frame authentication failed") ||
    m.includes("hmac verification failed") ||
    m.includes("auth_failed") ||
    m.includes("e_auth_failed")
  )
    return "E_AUTH_FAILED";
  if (m.includes("insufficient")) return "E_INSUFFICIENT_CAPACITY";
  if (m.includes("expired") || m.includes("e_expired")) return "E_EXPIRED";
  if (m.includes("revoked") || m.includes("e_revoked")) return "E_REVOKED";
  if (m.includes("consumed") || m.includes("e_consumed")) return "E_CONSUMED";
  if (m.includes("tampered") || m.includes("e_tampered")) return "E_TAMPERED";
  if (m.includes("geometry") || m.includes("e_geometry_mismatch"))
    return "E_GEOMETRY_MISMATCH";
  return "E_INTERNAL";
}
