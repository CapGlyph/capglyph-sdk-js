# @capglyph/sdk — TypeScript SDK for CapGlyph

TypeScript (Browser / Node / Cloudflare Workers) SDK for **CapGlyph** — image-native credential + stego payload infrastructure.

- Spec: [`CapGlyph/capglyph-spec` v1.0.0](https://github.com/CapGlyph/capglyph-spec) · Core: [`CapGlyph/capglyph-core` v0.1.0](https://github.com/CapGlyph/capglyph-core)
- Conformance: [`CapGlyph/capglyph-test-vectors` 1024/1024](https://github.com/CapGlyph/capglyph-test-vectors) — `vectors/{valid,invalid,malformed,tampered,expired,revoked}`

## Two-type design

| SDK type      | Transport                   | Implementation                                                                | Use case                                                                                                        |
| ------------- | --------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Local SDK** | WASM/FFI from Rust Core     | `src/local.ts` → `wasm/pkg/capglyph_core` (fallback `src/framing.ts` pure JS) | Browser/Workers `embed`/`verify` without server, offline seal/open                                              |
| **API SDK**   | Typed HTTP client (OpenAPI) | `src/client.ts` `CapglyphClient` (`fetch`)                                    | Node/edge calling `capglyphd` (`/v1/seal`, `/v1/open`, `/v1/embed`, `/v1/verify`, `/v1/extract`, `/v1/consume`) |

> Mirrors the SDK roadmap in `capglyph-spec/docs` and `capglyph-docs`: Local for credential-at-edge, API for centralized policy/consume/revoke.

## Install

```bash
npm install @capglyph/sdk
# or pin to dist-tag
npm install @capglyph/sdk@0.1.0
```

Requires Node 18+ (native `fetch`, `crypto`).

## Quickstart

### Local (WASM or JS fallback) — seal/open without server

```ts
import { LocalClient } from "@capglyph/sdk";

const kMac = Uint8Array.from(Buffer.from("42".repeat(32), "hex")); // HKDF-derived K_mac (capglyph_core::keying)
const payload = new TextEncoder().encode("credential-128b-token-....");

const local = new LocalClient();
await local.init(); // loads wasm/pkg/capglyph_core.js when built; otherwise JS fallback

const sealed = local.seal(payload, kMac); // Uint8Array: CBOR frame || HMAC-SHA256
const { header, payload: out } = local.open(sealed, kMac);
console.log(header); // { version: 1, payloadType: "Credential", flags: 0, payloadLen: 16 }
console.log(new TextDecoder().decode(out));
```

WASM build (optional — JS fallback is byte-identical for framing):

```bash
# from isolated monorepo /mnt/data/Workspace/Projects/capglyph
wasm-pack build --target web ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg
# re-run tests with WASM
npm test
```

See `wasm/README.md` for bundler vs web targets and Cloudflare Workers wiring.

### API (capglyphd) — typed client

```ts
import { CapglyphClient } from "@capglyph/sdk";

const client = new CapglyphClient({
  baseUrl: "https://capglyph.example.com",
  apiKey: process.env.CAPGLYPH_API_KEY,
});

// Seal via server (mirrors capglyph_core::framing::seal)
const { sealed_hex } = await client.seal({
  payload_hex: "001122...",
  k_mac_hex: "42".repeat(32),
  payload_type: 1,
});
const { payload_hex } = await client.open({
  sealed_hex,
  k_mac_hex: "42".repeat(32),
});

// Image carrier (DCT/DWT via capglyphd)
const pngBase64 = await readFile("cover.png", "base64");
const { image_base64 } = await client.embedImage({
  image_base64: pngBase64,
  mode: "dwt",
  payload_hex: "deadbeef",
  k_mac_hex: "...",
});
const { present } = await client.verifyImage({ image_base64, mode: "dwt" });
```

Error handling is fail-closed with `E_*` codes (spec §8):

```ts
import { CapglyphApiError } from "@capglyph/sdk";
try {
  await client.open({ sealed_hex: tamperedHex, k_mac_hex: kMacHex });
} catch (e) {
  if (e instanceof CapglyphApiError) console.error(e.code); // E_AUTH_FAILED, E_EXPIRED, ...
}
```

## Conformance

Vectors: `CapGlyph/capglyph-test-vectors` `1024` fixtures (`valid 256 / invalid 128 / malformed 128 / tampered 256 / expired 128 / revoked 128`). SDK must pass `valid` and fail others with the documented `E_*`.

```bash
# via Vitest (JS fallback, no WASM needed)
npm test

# verbose
npm run test:conformance

# standalone harness (no cargo)
node --loader ts-node/esm src/conformance.ts  # or vitest
python3 ../capglyph-test-vectors/tools/conformance.py --vectors ../capglyph-test-vectors/vectors
```

Expected:

```
valid     256/256 pass ✓
invalid   128/128 pass ✓
malformed 128/128 pass ✓
tampered  256/256 pass ✓
expired   128/128 pass ✓
revoked   128/128 pass ✓
total    1024/1024 vectors passed — conformance ✓
```

Vectors are resolved via `CAPGLYPH_VECTORS` or sibling `../capglyph-test-vectors/vectors` (isolated monorepo) or `/mnt/data/Workspace/Projects/capglyph/capglyph-test-vectors/vectors`.

## API Reference

### `src/framing.ts` (Local pure-JS, mirrors `capglyph_core::framing`)

- `seal(payload, params, kMac) → Uint8Array` — `CBOR([version, type, flags, len, payload]) || HMAC-SHA256`
- `open(sealed, kMac) → { header, payload }` — verify then CBOR decode, throws classified `E_*`
- `cborEncode / cborDecode / cborValidate`, `hmacTag / hmacVerify`, `classifyError`, `hexToBytes / bytesToHex`

### `src/local.ts`

- `LocalClient` — `seal`, `sealHex`, `open`, `openHex`, `validate`, `usingWasm`, `embedImage` (TODO until carrier WASM), `verifyImage`
- `local` singleton

### `src/client.ts`

- `CapglyphClient({ baseUrl, apiKey?, fetch? })` — `seal`, `open`, `validate`, `embedImage`, `verifyImage`, `extractImage`, `consume`, `revoke`, `info`, `health`
- `CapglyphApiError { code, status, message }`, `clientFromEnv()`

### `src/conformance.ts`

- `validateVector(vec)`, `validateVectors(vectors)`, `findVectorsRoot()`, `loadVectors(root)`

## Cloudflare Workers

```ts
import { LocalClient } from "@capglyph/sdk";
export default {
  async fetch(req: Request) {
    const local = new LocalClient();
    // Workers: pre-bundle wasm/pkg/capglyph_core_bg.wasm via wrangler --assets, or use JS fallback (no WASM needed for framing)
    const kMac = Uint8Array.from(atob(env.K_MAC_B64), (c) => c.charCodeAt(0));
    const sealed = local.seal(new TextEncoder().encode("hello"), kMac);
    return new Response(sealed);
  },
};
```

## Building

```bash
npm install
npm run build   # tsc → dist/
npm test        # vitest run (1024/1024)
```

## License

Apache-2.0 — same as `CapGlyph/capglyph-core`.
