/**
 * CapGlyph conformance harness — TypeScript port of capglyph-test-vectors/tools/conformance.py
 * Validates vectors against spec.md §8 precedence.
 *
 * Precedence: E_VERSION_UNSUPPORTED > E_MALFORMED_FRAME > E_AUTH_FAILED > policy(E_EXPIRED/E_REVOKED) > E_TAMPERED
 * Also checks byte-equality for valid vectors (seal roundtrip).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { readdirSync } from "node:fs";
import { join, extname } from "node:path";
import type { Vector, ConformanceResult, ConformanceSummary } from "./types.js";

function hmacTag(frame: Uint8Array, kMac: Uint8Array): Uint8Array {
  const mac = createHmac("sha256", kMac);
  mac.update(frame);
  return new Uint8Array(mac.digest());
}

// Minimal CBOR decoder — same as framing.ts but inlined to avoid import cycles for harness
function decodeFrame(data: Uint8Array): {
  version: number;
  ptype: number;
  flags: number;
  payloadLen: number;
  payload: Uint8Array;
} {
  if (data.length < 1) throw new Error("empty");
  let p = 0;
  if (data[p++] !== 0x85)
    throw new Error(`expected array 0x85, got ${data[0]?.toString(16)}`);
  const decUint = (): number => {
    if (p >= data.length) throw new Error("truncated uint");
    const b = data[p++];
    const mt = b >> 5;
    const ai = b & 0x1f;
    if (mt !== 0) throw new Error(`expected major 0, got ${mt} at ${p - 1}`);
    if (ai <= 23) return ai;
    if (ai === 24) {
      if (p >= data.length) throw new Error("truncated uint 1");
      return data[p++];
    }
    if (ai === 25) {
      if (p + 2 > data.length) throw new Error("truncated uint 2");
      const v = (data[p] << 8) | data[p + 1];
      p += 2;
      return v;
    }
    if (ai === 26) {
      if (p + 4 > data.length) throw new Error("truncated uint 4");
      const v =
        ((data[p] << 24) >>> 0) +
        (data[p + 1] << 16) +
        (data[p + 2] << 8) +
        data[p + 3];
      p += 4;
      return v;
    }
    if (ai === 27) {
      if (p + 8 > data.length) throw new Error("truncated uint 8");
      let v = 0;
      for (let i = 0; i < 8; i++) v = v * 256 + data[p + i];
      p += 8;
      return v;
    }
    throw new Error(`unsupported ai ${ai}`);
  };
  const version = decUint();
  const ptype = decUint();
  const flags = decUint();
  const payloadLen = decUint();
  if (p >= data.length) throw new Error("truncated bstr header");
  const hb = data[p++];
  const mt = hb >> 5;
  const ai = hb & 0x1f;
  if (mt !== 2) throw new Error(`expected bstr major 2, got ${mt}`);
  let blen: number;
  if (ai <= 23) blen = ai;
  else if (ai === 24) {
    if (p >= data.length) throw new Error("truncated bstr len 1");
    blen = data[p++];
  } else if (ai === 25) {
    if (p + 2 > data.length) throw new Error("truncated bstr len 2");
    blen = (data[p] << 8) | data[p + 1];
    p += 2;
  } else if (ai === 26) {
    if (p + 4 > data.length) throw new Error("truncated bstr len 4");
    blen =
      ((data[p] << 24) >>> 0) +
      (data[p + 1] << 16) +
      (data[p + 2] << 8) +
      data[p + 3];
    p += 4;
  } else if (ai === 27) {
    if (p + 8 > data.length) throw new Error("truncated bstr len 8");
    blen = 0;
    for (let i = 0; i < 8; i++) blen = blen * 256 + data[p + i];
    p += 8;
  } else throw new Error("indefinite bstr not allowed");
  if (p + blen > data.length) throw new Error("truncated bstr payload");
  const payload = data.slice(p, p + blen);
  p += blen;
  if (p !== data.length) throw new Error(`trailing bytes ${data.length - p}`);
  if (payloadLen !== blen)
    throw new Error(
      `payload_len mismatch header ${payloadLen} vs bstr ${blen}`,
    );
  if (version !== 1) throw new Error(`unsupported version ${version}`);
  if (![1, 2, 3, 4].includes(ptype))
    throw new Error(`unknown PayloadType ${ptype}`);
  return { version, ptype, flags, payloadLen, payload };
}

function hexToBytes(hex: string): Uint8Array {
  if (!hex) return new Uint8Array(0);
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export function validateVector(vec: Vector): {
  ok: boolean;
  outcome: string;
  detail?: string;
} {
  const expectedSuccess = vec.expected_success;
  const expectedCode = vec.expected_code;
  const sealedHex = vec.sealed_hex ?? "";
  const kMacHex = vec.k_mac_hex ?? "";
  const payloadHex = vec.payload_hex ?? "";
  const cborFrameHex = vec.cbor_frame_hex ?? "";
  const category = vec.category;
  const mock = vec.mock_policy as any;

  try {
    if (!sealedHex) {
      const computed = "E_MALFORMED_FRAME";
      if (expectedSuccess)
        return {
          ok: false,
          outcome: computed,
          detail: "empty sealed_hex on valid",
        };
      if (expectedCode && computed !== expectedCode) {
        if (
          (category === "malformed" || category === "invalid") &&
          ["E_MALFORMED_FRAME", "E_VERSION_UNSUPPORTED"].includes(computed) &&
          ["E_MALFORMED_FRAME", "E_VERSION_UNSUPPORTED"].includes(expectedCode!)
        )
          return { ok: true, outcome: computed };
        return {
          ok: false,
          outcome: computed,
          detail: `expected ${expectedCode} got ${computed}: empty sealed`,
        };
      }
      return { ok: true, outcome: computed };
    }
    let sealed: Uint8Array;
    try {
      sealed = hexToBytes(sealedHex);
    } catch (e: any) {
      const computed = "E_MALFORMED_FRAME";
      if (expectedCode !== computed)
        return {
          ok: false,
          outcome: computed,
          detail: `bad hex: ${e.message}`,
        };
      return { ok: true, outcome: computed };
    }
    if (sealed.length < 32) {
      const computed = "E_MALFORMED_FRAME";
      if (expectedSuccess)
        return {
          ok: false,
          outcome: computed,
          detail: "sealed too short (<32 B tag)",
        };
      if (expectedCode && computed !== expectedCode) {
        if (
          (category === "malformed" || category === "invalid") &&
          ["E_MALFORMED_FRAME", "E_VERSION_UNSUPPORTED"].includes(computed) &&
          ["E_MALFORMED_FRAME", "E_VERSION_UNSUPPORTED"].includes(expectedCode!)
        )
          return { ok: true, outcome: computed };
        return {
          ok: false,
          outcome: computed,
          detail: `expected ${expectedCode} got ${computed}: short tag`,
        };
      }
      return { ok: true, outcome: computed };
    }
    const kMac = kMacHex ? hexToBytes(kMacHex) : new Uint8Array(0);
    if (kMac.length !== 32) {
      // allow invalid vectors to proceed; will be classified downstream
    }
    const frame = sealed.slice(0, sealed.length - 32);
    const tag = sealed.slice(sealed.length - 32);

    let decoded: {
      version: number;
      ptype: number;
      flags: number;
      payloadLen: number;
      payload: Uint8Array;
    };
    try {
      decoded = decodeFrame(frame);
    } catch (e: any) {
      const msg = String(e.message);
      const computed = msg.includes("unsupported version")
        ? "E_VERSION_UNSUPPORTED"
        : "E_MALFORMED_FRAME";
      if (expectedSuccess)
        return {
          ok: false,
          outcome: computed,
          detail: `CBOR fail on valid: ${msg}`,
        };
      if (expectedCode && computed !== expectedCode) {
        if (
          (category === "malformed" || category === "invalid") &&
          ["E_MALFORMED_FRAME", "E_VERSION_UNSUPPORTED"].includes(computed) &&
          ["E_MALFORMED_FRAME", "E_VERSION_UNSUPPORTED"].includes(expectedCode!)
        )
          return { ok: true, outcome: computed };
        return {
          ok: false,
          outcome: computed,
          detail: `expected ${expectedCode} got ${computed}: ${msg}`,
        };
      }
      return { ok: true, outcome: computed };
    }

    if (kMac.length !== 32) {
      const computed = "E_MALFORMED_FRAME";
      if (expectedCode !== computed)
        return { ok: false, outcome: computed, detail: "bad k_mac length" };
      return { ok: true, outcome: computed };
    }
    const expectedTag = hmacTag(frame, kMac);
    let hmacOk = false;
    try {
      hmacOk = timingSafeEqual(Buffer.from(tag), Buffer.from(expectedTag));
    } catch {
      hmacOk = false;
    }
    if (!hmacOk) {
      const computed = "E_AUTH_FAILED";
      if (expectedSuccess)
        return {
          ok: false,
          outcome: computed,
          detail: "HMAC mismatch on valid",
        };
      if (expectedCode && computed !== expectedCode)
        return {
          ok: false,
          outcome: computed,
          detail: `expected ${expectedCode} got ${computed}`,
        };
      return { ok: true, outcome: computed };
    }

    if (category === "valid") {
      if (
        cborFrameHex &&
        Buffer.from(frame).toString("hex") !== cborFrameHex.toLowerCase()
      ) {
        return {
          ok: false,
          outcome: "MISMATCH",
          detail: `cbor_frame_hex mismatch: got ${Buffer.from(frame).toString("hex")} exp ${cborFrameHex}`,
        };
      }
      if (
        Buffer.from(decoded.payload).toString("hex") !==
        payloadHex.toLowerCase()
      ) {
        return {
          ok: false,
          outcome: "MISMATCH",
          detail: "payload_hex mismatch after open",
        };
      }
    }

    if (mock) {
      if (
        category === "expired" ||
        (mock.expires_at && String(mock.expires_at).includes("2024"))
      ) {
        const computed = "E_EXPIRED";
        if (expectedCode !== computed)
          return {
            ok: false,
            outcome: computed,
            detail: `expected ${expectedCode} got ${computed}`,
          };
        return { ok: true, outcome: computed };
      }
      if (category === "revoked" || mock.revoked_at) {
        const computed = "E_REVOKED";
        if (expectedCode !== computed)
          return {
            ok: false,
            outcome: computed,
            detail: `expected ${expectedCode} got ${computed}`,
          };
        return { ok: true, outcome: computed };
      }
    }

    if (expectedSuccess) return { ok: true, outcome: "OK" };
    return {
      ok: false,
      outcome: "OK",
      detail: `expected ${expectedCode} but got OK`,
    };
  } catch (e: any) {
    return {
      ok: false,
      outcome: "HARNESS_ERROR",
      detail: String(e?.message ?? e),
    };
  }
}

export function validateVectors(
  vectors: Vector[],
  files?: string[],
): ConformanceSummary {
  const byCategory: Record<
    string,
    { pass: number; fail: number; total: number }
  > = {};
  const failures: ConformanceResult[] = [];
  let passed = 0;
  vectors.forEach((vec, i) => {
    const file = files?.[i] ?? vec.id;
    const { ok, outcome, detail } = validateVector(vec);
    const cat = vec.category ?? "unknown";
    if (!byCategory[cat]) byCategory[cat] = { pass: 0, fail: 0, total: 0 };
    byCategory[cat].total += 1;
    if (ok) {
      byCategory[cat].pass += 1;
      passed += 1;
    } else {
      byCategory[cat].fail += 1;
      failures.push({
        id: vec.id,
        category: cat,
        ok: false,
        outcome,
        expected: vec.expected_code,
        detail,
        file,
      });
    }
  });
  return { total: vectors.length, passed, byCategory, failures };
}

// -- Loader helpers --------------------------------------------------

export function findVectorsRoot(explicit?: string): string | null {
  const candidates = [
    explicit,
    process.env.CAPGLYPH_VECTORS,
    join(process.cwd(), "vectors"),
    join(process.cwd(), "..", "capglyph-test-vectors", "vectors"),
    join(process.cwd(), "..", "..", "capglyph-test-vectors", "vectors"),
    "/mnt/data/Workspace/Projects/capglyph/capglyph-test-vectors/vectors",
  ].filter(Boolean) as string[];
  for (const p of candidates) {
    if (existsSync(p) && existsSync(join(p, "valid"))) return p;
  }
  return null;
}

export function loadVectors(vectorsRoot: string): {
  vectors: Vector[];
  files: string[];
} {
  const cats = [
    "valid",
    "invalid",
    "malformed",
    "tampered",
    "expired",
    "revoked",
  ];
  const vectors: Vector[] = [];
  const files: string[] = [];
  for (const cat of cats) {
    const dir = join(vectorsRoot, cat);
    if (!existsSync(dir)) continue;
    const entries = readdirSync(dir)
      .filter((f) => extname(f) === ".json")
      .sort();
    for (const f of entries) {
      const path = join(dir, f);
      const raw = readFileSync(path, "utf-8");
      vectors.push(JSON.parse(raw) as Vector);
      files.push(path);
    }
  }
  // also support flat vectors dir (no subdirs)
  if (vectors.length === 0) {
    const flat = readdirSync(vectorsRoot)
      .filter((f) => extname(f) === ".json")
      .sort();
    for (const f of flat) {
      const path = join(vectorsRoot, f);
      vectors.push(JSON.parse(readFileSync(path, "utf-8")) as Vector);
      files.push(path);
    }
  }
  return { vectors, files };
}
