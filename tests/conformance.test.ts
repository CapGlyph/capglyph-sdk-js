/**
 * CapGlyph conformance test — vitest runner for TS SDK
 * Asserts 1024/1024 vectors from CapGlyph/capglyph-test-vectors via src/conformance.ts
 *
 * Vectors are located via CAPGLYPH_VECTORS env or sibling ../capglyph-test-vectors/vectors
 * (isolated monorepo layout: /mnt/data/Workspace/Projects/capglyph/).
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateVector, findVectorsRoot, loadVectors } from "../src/conformance.js";

describe("conformance — capglyph-test-vectors (1024)", () => {
  const vectorsRoot = findVectorsRoot();

  it("finds vectors root", () => {
    expect(
      vectorsRoot,
      `vectors not found — set CAPGLYPH_VECTORS or ensure sibling capglyph-test-vectors exists (checked ${process.cwd()})`,
    ).toBeTruthy();
  });

  it("loads 1024 vectors with expected splits", () => {
    if (!vectorsRoot) return;
    const { vectors } = loadVectors(vectorsRoot);
    expect(vectors.length).toBe(1024);
    const byCat: Record<string, number> = {};
    for (const v of vectors) byCat[v.category] = (byCat[v.category] ?? 0) + 1;
    expect(byCat).toEqual({
      valid: 256,
      invalid: 128,
      malformed: 128,
      tampered: 256,
      expired: 128,
      revoked: 128,
    });
  });

  it("passes 1024/1024 — every vector matches expected_code/expected_success", () => {
    if (!vectorsRoot) return;
    const { vectors, files } = loadVectors(vectorsRoot);
    const failures: string[] = [];
    vectors.forEach((vec, i) => {
      const { ok, outcome, detail } = validateVector(vec);
      if (!ok)
        failures.push(
          `${vec.id} exp=${vec.expected_code ?? "OK"} got=${outcome} ${detail ?? ""} @ ${files[i]}`,
        );
    });
    if (failures.length) {
      // Print first 20 failures for debugging
      console.error(
        `Conformance failures (${failures.length}):\n` + failures.slice(0, 20).join("\n"),
      );
    }
    expect(failures, failures.join("\n")).toEqual([]);
    expect(vectors.length).toBe(1024);
  });

  it("validates manifest SHA256 if present", () => {
    const manifestPath = vectorsRoot ? join(vectorsRoot, "..", "manifest.json") : null;
    if (!manifestPath || !existsSync(manifestPath)) return; // optional
    const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
    expect(manifest.count).toBe(1024);
    expect(manifest.splits).toEqual({
      valid: 256,
      invalid: 128,
      malformed: 128,
      tampered: 256,
      expired: 128,
      revoked: 128,
    });
  });
});

describe("framing — seal/open byte-equality (local JS fallback)", () => {
  it("seal/open roundtrip 16B credential (mirrors capglyph-core framing.rs seal_open_roundtrip)", async () => {
    const { seal, open } = await import("../src/framing.js");
    const kMac = new Uint8Array(32).fill(0x42);
    const payload = Uint8Array.from(Buffer.from("00112233445566778899aabbccddeeff", "hex"));
    const sealed = seal(payload, { version: 1, payloadType: "Credential", flags: 0 }, kMac);
    expect(Buffer.from(sealed).toString("hex")).toBe(
      "85010100105000112233445566778899aabbccddeeff7d28c792e0e52a6acfd5a2dcb99c585bbfdf88da0d4686f333c7af22c7f71a7f",
    );
    const { header, payload: out } = open(sealed, kMac);
    expect(header.version).toBe(1);
    expect(header.payloadType).toBe("Credential");
    expect(header.payloadLen).toBe(16);
    expect(Buffer.from(out).toString("hex")).toBe("00112233445566778899aabbccddeeff");
  });

  it("tamper detection (single bit flip → E_AUTH_FAILED)", async () => {
    const { seal, open, classifyError } = await import("../src/framing.js");
    const kMac = new Uint8Array(32).fill(0x42);
    const sealed = seal(
      Buffer.from("hello credential"),
      { version: 1, payloadType: "Credential", flags: 0 },
      kMac,
    );
    const tampered = Uint8Array.from(sealed);
    tampered[5] ^= 0x01;
    let err = "";
    try {
      open(tampered, kMac);
    } catch (e: any) {
      err = String(e.message);
    }
    expect(classifyError(err)).toBe("E_AUTH_FAILED");
  });

  it("covers payload boundaries and malformed authenticated frames", async () => {
    const { seal, open, cborDecode } = await import("../src/framing.js");
    const key = new Uint8Array(32).fill(0x42);
    const params = { version: 1, payloadType: "Credential" as const, flags: 0 };
    for (const length of [0, 16, 23, 24, 255, 256, 65535]) {
      const payload = new Uint8Array(length).fill(0xab);
      expect(open(seal(payload, params, key), key).payload).toEqual(payload);
    }
    expect(() => seal(new Uint8Array(65536), params, key)).toThrow("payload too large");
    const frame = seal(Uint8Array.of(0x01), params, key).slice(0, -32);
    expect(() => cborDecode(Uint8Array.from([...frame, 0]))).toThrow("trailing bytes");
    const noncanonical = Uint8Array.from([frame[0], 0x18, 1, ...frame.slice(2)]);
    expect(() => cborDecode(noncanonical)).toThrow("non-canonical");
    expect(() => open(new Uint8Array(31), key)).toThrow("too short");
    expect(() => open(seal(Uint8Array.of(1), params, key), new Uint8Array(32))).toThrow(
      "HMAC verification failed",
    );
  });

  it("covers types, flags, nested payload, unknown type, and version precedence", async () => {
    const { seal, open, hmacTag } = await import("../src/framing.js");
    const key = new Uint8Array(32).fill(0x42);
    const nested = Uint8Array.from([0xa1, 0, 0x50, ...Array.from({ length: 16 }, (_, i) => i)]);
    for (const payloadType of ["Credential", "Pointer", "Message", "Locator"] as const) {
      for (const flags of [0, 1, 255]) {
        const result = open(seal(nested, { version: 1, payloadType, flags }, key), key);
        expect(result.header).toMatchObject({ payloadType, flags });
        expect(result.payload).toEqual(nested);
      }
    }
    const versionTwo = seal(
      Uint8Array.of(1),
      { version: 2, payloadType: "Credential", flags: 0 },
      key,
    );
    expect(() => open(versionTwo, key)).toThrow("unsupported version");
    expect(() => open(versionTwo, new Uint8Array(32))).toThrow("HMAC verification failed");
    const frame = Uint8Array.from([0x85, 1, 5, 0, 1, 0x41, 1]);
    expect(() => open(Uint8Array.from([...frame, ...hmacTag(frame, key)]), key)).toThrow(
      "unknown PayloadType",
    );
  });
});
