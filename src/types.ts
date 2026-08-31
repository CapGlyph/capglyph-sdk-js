/**
 * CapGlyph SDK types — mirrors capglyph-spec v1.0.0 + capglyph-core 0.1.0
 * Spec: CapGlyph/capglyph-spec spec.md §2/§3/§4/§8
 */

export type PayloadType = "Credential" | "Pointer" | "Message" | "Locator";
export const PayloadTypeId: Record<PayloadType, number> = {
  Credential: 1,
  Pointer: 2,
  Message: 3,
  Locator: 4,
};
export const PayloadTypeFromId: Record<number, PayloadType> = {
  1: "Credential",
  2: "Pointer",
  3: "Message",
  4: "Locator",
};

export type ErrorCode =
  | "E_VERSION_UNSUPPORTED"
  | "E_MALFORMED_FRAME"
  | "E_AUTH_FAILED"
  | "E_INSUFFICIENT_CAPACITY"
  | "E_EXPIRED"
  | "E_REVOKED"
  | "E_CONSUMED"
  | "E_TAMPERED"
  | "E_GEOMETRY_MISMATCH"
  | "E_INTERNAL";

export interface FrameHeader {
  version: number;
  payloadType: PayloadType;
  flags: number;
  payloadLen: number;
}

export interface Vector {
  id: string;
  category:
    "valid" | "invalid" | "malformed" | "tampered" | "expired" | "revoked";
  spec_version: string;
  protocol_version: number;
  payload_type: string;
  payload_type_id: number;
  flags: number;
  payload_hex: string;
  payload_len: number;
  k_mac_hex: string;
  cbor_frame_hex: string;
  tag_hex: string;
  sealed_hex: string;
  expected_success: boolean;
  expected_code: string | null;
  expected_error: string | null;
  description: string;
  carrier: string;
  ecc_profile: string;
  threshold: number;
  mock_policy: null | {
    not_before?: string;
    expires_at?: string;
    revoked_at?: string;
    now?: string;
    reason?: string;
  };
  tamper?: { flipped_byte: number; in: string; base_id: string };
}

export interface ConformanceResult {
  id: string;
  category: string;
  ok: boolean;
  outcome: string;
  expected: string | null;
  detail?: string;
  file: string;
}

export interface ConformanceSummary {
  total: number;
  passed: number;
  byCategory: Record<string, { pass: number; fail: number; total: number }>;
  failures: ConformanceResult[];
}
