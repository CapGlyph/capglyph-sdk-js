# CapGlyph WASM bridge (capglyph-core → TypeScript Local SDK)

The Local SDK (`src/local.ts`) prefers a `wasm-pack` build of `capglyph-core` when available, falling back to the pure-JS `src/framing.ts` implementation for conformance and testing.

## Build (browser + Node)

From the isolated monorepo (`/mnt/data/Workspace/Projects/capglyph`):

```bash
# Browser (web) target — for zola-site, Cloudflare Workers, Vite, etc.
wasm-pack build --target web ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg

# Node/bundler target — for Vitest, Node SDK, Next.js
wasm-pack build --target bundler ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg
# or
wasm-pack build --target nodejs ../capglyph-core --out-dir ../capglyph-sdk-js/wasm/pkg
```

Requires `wasm-pack 0.15+` and `wasm32-unknown-unknown` toolchain:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## What the WASM exposes (planned)

`capglyph-core` will expose via `wasm-bindgen`:

- `seal(payload: Uint8Array, version: u8, payload_type: u8, flags: u8, k_mac: Uint8Array) -> Uint8Array`
- `open(sealed: Uint8Array, k_mac: Uint8Array) -> Uint8Array` (header+payload)
- `validate_frame(bytes: Uint8Array) -> FrameHeader`
- Carrier: `embed_image(bytes, mode, placement, k_mac) -> Uint8Array` (once image crate is bound; see CTX-0017 wasm bundle spike)

Until the carrier binding lands, image APIs in `src/local.ts` throw with a TODO and the SDK uses the HTTP API client (`src/client.ts`) for `embedImage`/`verifyImage`.

## Integration

```ts
import { LocalClient } from "@capglyph/sdk";
const local = new LocalClient();
await local.init(); // loads wasm/pkg/capglyph_core.js if present
const sealed = local.seal(payload, kMac);
const { payload: out } = local.open(sealed, kMac);
```

## Verification

```bash
npm test            # vitest — includes 1024/1024 conformance (JS fallback passes without WASM)
npm run build       # tsc → dist/
```

See `capglyph-spec/spec.md` §3/§8 and `capglyph-core/src/framing.rs` for the canonical framing.
