/**
 * CapGlyph API SDK — typed HTTP client for capglyphd
 * OpenAPI surface: /v1/{seal,open,embed,verify,extract,info,consume,revoke} (see capglyph-spec/docs + capglyph-cli/crates/capglyph-server)
 *
 * Works in Browser, Node 18+, and Cloudflare Workers (fetch-native, no Node deps).
 */

export type CapglyphdConfig = {
  baseUrl: string; // e.g. "https://capglyph.example.com" or "http://localhost:8080"
  apiKey?: string; // Bearer token for capglyphd auth (X-API-Key or Authorization: Bearer)
  fetch?: typeof globalThis.fetch; // injectable for testing/workers
};

export type SealRequest = {
  payload_hex: string;
  k_mac_hex: string;
  version?: number;
  payload_type?: number; // 1..4
  flags?: number;
};

export type SealResponse = {
  sealed_hex: string;
  cbor_frame_hex: string;
  tag_hex: string;
};

export type OpenRequest = {
  sealed_hex: string;
  k_mac_hex: string;
};

export type OpenResponse = {
  payload_hex: string;
  header: {
    version: number;
    payload_type: number;
    flags: number;
    payload_len: number;
  };
};

export type ApiError = {
  code: string; // E_*
  message: string;
  status: number;
};

export class CapglyphApiError extends Error {
  code: string;
  status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "CapglyphApiError";
    this.code = code;
    this.status = status;
  }
}

export class CapglyphClient {
  private baseUrl: string;
  private apiKey?: string;
  private fetchFn: typeof globalThis.fetch;

  constructor(config: CapglyphdConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.fetchFn = config.fetch ?? globalThis.fetch;
    if (!this.fetchFn)
      throw new Error("fetch is not available — provide config.fetch");
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;
    const res = await this.fetchFn(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // non-JSON error body
    }
    if (!res.ok) {
      const code = json?.code ?? json?.error ?? `E_HTTP_${res.status}`;
      const message = json?.message ?? json?.error ?? text ?? res.statusText;
      throw new CapglyphApiError(code, message, res.status);
    }
    return json as T;
  }

  // -- Framing (pure, no image) --------------------------------

  /** Seal payload via server (mirrors capglyph_core::framing::seal). */
  seal(req: SealRequest): Promise<SealResponse> {
    return this.request<SealResponse>("POST", "/v1/seal", req);
  }

  /** Open sealed envelope via server. Fail-closed maps to CapglyphApiError with E_* code. */
  open(req: OpenRequest): Promise<OpenResponse> {
    return this.request<OpenResponse>("POST", "/v1/open", req);
  }

  /** Validate frame header without key (preflight). */
  validate(
    sealedHex: string,
  ): Promise<{
    valid: boolean;
    header?: OpenResponse["header"];
    code?: string;
  }> {
    return this.request("POST", "/v1/validate", { sealed_hex: sealedHex });
  }

  // -- Image carrier (DCT/DWT) --------------------------------

  /** Embed payload into image (PNG/JPEG) via server. Returns PNG bytes as base64. */
  embedImage(params: {
    image_base64: string;
    mode: "dct" | "dwt" | "alpha";
    payload_hex: string;
    k_mac_hex: string;
  }): Promise<{ image_base64: string }> {
    return this.request("POST", "/v1/embed", params);
  }

  /** Verify watermark presence in image. */
  verifyImage(params: {
    image_base64: string;
    mode: "dct" | "dwt" | "alpha";
    k_mac_hex?: string;
  }): Promise<{ present: boolean; code?: string; metrics?: unknown }> {
    return this.request("POST", "/v1/verify", params);
  }

  /** Extract bearer payload from image (geometry-free PRNG ID). */
  extractImage(params: {
    image_base64: string;
    mode: "dct" | "dwt";
    id_length?: number;
  }): Promise<{ payload_hex: string }> {
    return this.request("POST", "/v1/extract", params);
  }

  // -- Credential lifecycle (capglyphd DB) --------------------

  consume(params: {
    token_id: string;
    now?: string;
  }): Promise<{ consumed: boolean; code?: string }> {
    return this.request("POST", "/v1/consume", params);
  }

  revoke(params: {
    token_id: string;
    reason?: string;
  }): Promise<{ revoked: boolean }> {
    return this.request("POST", "/v1/revoke", params);
  }

  info(params: { image_base64: string; mode?: string }): Promise<unknown> {
    return this.request("POST", "/v1/info", params);
  }

  // -- Health -------------------------------------------------

  health(): Promise<{ status: string; version: string }> {
    return this.request("GET", "/health");
  }
}

/** Convenience: create client from env (CAPGLYPH_API_URL / CAPGLYPH_API_KEY). */
export function clientFromEnv(
  fetchImpl?: typeof globalThis.fetch,
): CapglyphClient {
  const baseUrl = process.env.CAPGLYPH_API_URL ?? "http://localhost:8080";
  const apiKey = process.env.CAPGLYPH_API_KEY;
  return new CapglyphClient({ baseUrl, apiKey, fetch: fetchImpl });
}
