// AUTO-GENERATED from packages/contracts/schemas/*.schema.json
// Do NOT edit by hand — run: npm run generate

// --- error_response.schema.json ---
/**
 * Unified error response shape used by all REST endpoints across every service (design.md §5).
 */
export interface ErrorResponse {
  error: {
    /**
     * Machine-readable error code.
     */
    code: string;
    /**
     * Human-readable error description.
     */
    message: string;
    /**
     * Optional structured details.
     */
    details?: {
      [k: string]: unknown;
    };
  };
}


// --- extraction_envelope.schema.json ---
/**
 * Common Intermediate Extraction Envelope — emitted by both hot and cold path. The contract that lets normalization treat both identically.
 */
export interface ExtractionEnvelope {
  lineage_id: string;
  path_taken: "HOT" | "COLD";
  /**
   * E.g. cisco_asa, unknown_v1
   */
  source_type: string;
  /**
   * Key-value pairs of extracted field names to their string values.
   */
  extracted_fields: {
    [k: string]: string;
  };
  /**
   * Per-field confidence scores. Hot-path scores are always 1.0.
   */
  confidence_scores: {
    [k: string]: number;
  };
  /**
   * Semver of the parser/pack that produced this extraction.
   */
  parser_version: string;
}


// --- merkle_leaf.v1.schema.json ---
/**
 * Bus message: ulpf.merkle.leaf.v1 — leaf hash published by ingestion-svc for Merkle tree batching.
 */
export interface MerkleLeafV1 {
  /**
   * UUIDv4, same as the raw_events row.
   */
  lineage_id: string;
  /**
   * Hex-encoded SHA-256 of the raw bytes.
   */
  sha256_hash: string;
  /**
   * ISO-8601 UTC with microsecond precision.
   */
  ingestion_timestamp: string;
}


// --- ocsf_event.v1.schema.json ---
/**
 * Bus message: ulpf.ocsf.events.v1 — OCSF Class 4001 (Network Activity) with ULPF extensions.
 */
export interface OcsfNetworkActivityV1 {
  /**
   * OCSF activity ID.
   */
  activity_id: number;
  /**
   * Human-readable activity name.
   */
  activity_name: string;
  /**
   * OCSF category: Network Activity.
   */
  category_uid: 4;
  /**
   * OCSF class: Network Activity.
   */
  class_uid: 4001;
  class_name: "Network Activity";
  /**
   * OCSF severity (0=Unknown to 6=Fatal).
   */
  severity_id: number;
  /**
   * Event timestamp as epoch milliseconds. Required by OCSF.
   */
  time: number;
  src_endpoint: Endpoint;
  dst_endpoint: Endpoint;
  connection_info?: {
    protocol_num?: number;
    protocol_name?: string;
  };
  metadata: {
    version: string;
    /**
     * Must always equal _lineage_id.
     */
    uid: string;
    product: {
      vendor_name: string;
      name: string;
    };
  };
  /**
   * URI to the raw store location.
   */
  raw_data?: string;
  /**
   * ULPF extension: per-field confidence scores.
   */
  _confidence?: {
    [k: string]: number;
  };
  /**
   * ULPF extension: lineage ID. Always identical to metadata.uid.
   */
  _lineage_id: string;
  /**
   * Vendor-specific unmapped attributes preserving complete raw fidelity.
   */
  unmapped?: Record<string, unknown>;
}
export interface Endpoint {
  ip?: string;
  port?: number;
  hostname?: string;
}


// --- pack_lifecycle.v1.schema.json ---
/**
 * Bus message: ulpf.pack.lifecycle.v1 — emitted on pack state transitions.
 */
export interface PackLifecycleV1 {
  /**
   * E.g. cisco_asa_v1.3.0
   */
  pack_id: string;
  event_type: "pack_created" | "pack_confirmed" | "pack_updated" | "pack_rolled_back" | "pack_quarantined";
  /**
   * Identity of the actor. Never anonymous — e.g. analyst:jdoe, system:auto-onboarding
   */
  actor: string;
  /**
   * SHA-256 hash of the event, anchored on-chain.
   */
  event_hash: string;
  /**
   * ISO-8601 UTC.
   */
  occurred_at: string;
}


// --- raw_ingest.v1.schema.json ---
/**
 * Bus message: ulpf.raw.ingest.v1 — raw ingestion envelope published by ingestion-svc.
 */
export interface RawIngestV1 {
  /**
   * UUIDv4, generated once at ingestion, never reused.
   */
  lineage_id: string;
  /**
   * Base64-encoded raw bytes. Omitted (null) when payload exceeds bus.max_inline_bytes — use storage_pointer instead.
   */
  raw_bytes_b64?: string | null;
  /**
   * URI to the raw store location: raw_store://chunk_<id>/offset_<n>
   */
  storage_pointer?: string;
  /**
   * Hex-encoded SHA-256 of the raw bytes.
   */
  sha256_hash: string;
  /**
   * ISO-8601 UTC with microsecond precision.
   */
  ingestion_timestamp: string;
  /**
   * Source IP address (IPv4 or IPv6).
   */
  source_ip: string;
  source_port: number;
  transport_protocol: "UDP" | "TCP" | "TLS" | "HTTP";
  /**
   * Detected character encoding. Metadata only — never used to transform stored bytes.
   */
  char_encoding: string;
}


// --- review_queue.v1.schema.json ---
/**
 * Bus message: ulpf.review.queue.v1 — cold-path review item for analyst confirmation.
 */
export interface ReviewQueueV1 {
  /**
   * Null on initial publish; populated once persisted in the review_queue table.
   */
  review_id?: number | null;
  lineage_id: string;
  extraction_id: number;
  /**
   * Drain cluster ID, zero-padded integer suffix.
   */
  cluster_id: string;
  /**
   * Per-field candidate OCSF mapping with similarity scores.
   */
  candidate_mapping: {
    [k: string]: {
      /**
       * Dot-notation OCSF attribute path.
       */
      candidate_ocsf_attribute: string;
      similarity_score: number;
      alternate_candidates?: {
        attribute: string;
        similarity_score: number;
      }[];
    };
  };
  /**
   * URI to a representative raw sample.
   */
  sample_raw_pointer: string;
}

