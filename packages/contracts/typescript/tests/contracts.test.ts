/**
 * Round-trip validation tests for ULPF contracts (TypeScript side).
 *
 * M0 acceptance criteria: "A sample payload for each contract round-trips
 * (encode → validate → decode) in both Python and TypeScript against
 * the *same* generated types."
 */

import Ajv from "ajv";
import addFormats from "ajv-formats";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import type {
  ErrorResponse,
  ExtractionEnvelope,
  MerkleLeafV1,
  OcsfNetworkActivityV1,
  PackLifecycleV1,
  RawIngestV1,
  ReviewQueueV1,
} from "../src/index.js";

// ── Setup ──

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const SCHEMA_DIR = resolve(__dirname, "../../schemas");

function loadSchema(name: string): Record<string, unknown> {
  const raw = JSON.parse(readFileSync(join(SCHEMA_DIR, name), "utf-8"));
  // Remove $schema and $id — AJV doesn't handle Draft 2020-12 $schema meta-ref
  // and $id causes "already exists" on recompile. The schemas still validate correctly.
  const { $schema, $id, ...rest } = raw;
  return rest;
}

function createValidator() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv;
}

// ── Sample payloads (identical to Python tests) ──

const LINEAGE_ID = "550e8400-e29b-41d4-a716-446655440000";

const SAMPLE_RAW_INGEST: RawIngestV1 = {
  lineage_id: LINEAGE_ID,
  raw_bytes_b64: "SEVMTE8gV09STEQ=",
  storage_pointer: "raw_store://chunk_20260925_01/offset_42",
  sha256_hash: "a".repeat(64),
  ingestion_timestamp: "2026-09-25T09:12:44.123456Z",
  source_ip: "203.0.113.5",
  source_port: 51422,
  transport_protocol: "UDP",
  char_encoding: "UTF-8",
};

const SAMPLE_MERKLE_LEAF: MerkleLeafV1 = {
  lineage_id: LINEAGE_ID,
  sha256_hash: "b".repeat(64),
  ingestion_timestamp: "2026-09-25T09:12:44.123456Z",
};

const SAMPLE_EXTRACTION_ENVELOPE: ExtractionEnvelope = {
  lineage_id: LINEAGE_ID,
  path_taken: "HOT",
  source_type: "cisco_asa",
  extracted_fields: { src_ip: "10.1.1.1", dst_ip: "8.8.8.8", action: "Deny" },
  confidence_scores: { src_ip: 1.0, dst_ip: 1.0, action: 0.95 },
  parser_version: "1.3.0",
};

const SAMPLE_REVIEW_QUEUE: ReviewQueueV1 = {
  review_id: null,
  lineage_id: LINEAGE_ID,
  extraction_id: 1,
  cluster_id: "drain-cluster-0042",
  candidate_mapping: {
    field_raw_token_3: {
      candidate_ocsf_attribute: "dst_endpoint.hostname",
      similarity_score: 0.71,
      alternate_candidates: [
        { attribute: "src_endpoint.hostname", similarity_score: 0.68 },
      ],
    },
  },
  sample_raw_pointer: "raw_store://chunk_20260925_01/offset_42",
};

const SAMPLE_PACK_LIFECYCLE: PackLifecycleV1 = {
  pack_id: "cisco_asa_v1.3.0",
  event_type: "pack_created",
  actor: "analyst:jdoe",
  event_hash: "c".repeat(64),
  occurred_at: "2026-09-25T09:12:44Z",
};

const SAMPLE_OCSF_EVENT: OcsfNetworkActivityV1 = {
  activity_id: 5,
  activity_name: "Refuse",
  category_uid: 4,
  class_uid: 4001,
  class_name: "Network Activity",
  severity_id: 4,
  time: 1790328764123,
  src_endpoint: { ip: "10.1.1.50", port: 49823 },
  dst_endpoint: { ip: "8.8.8.8", port: 443 },
  connection_info: { protocol_num: 6, protocol_name: "tcp" },
  metadata: {
    version: "1.2.0",
    uid: LINEAGE_ID,
    product: { vendor_name: "Cisco", name: "ASA Firewall" },
  },
  raw_data: "raw_store://chunk_20260925_01/offset_42",
  _confidence: { "src_endpoint.ip": 1.0, activity_id: 0.95 },
  _lineage_id: LINEAGE_ID,
};

const SAMPLE_ERROR_RESPONSE: ErrorResponse = {
  error: {
    code: "CONFLICT",
    message: "Another analyst already confirmed this cluster.",
    details: { winner: "analyst:alice" },
  },
};

// ── Tests ──

describe("Contract round-trip tests", () => {
  const cases: Array<{
    name: string;
    schema: string;
    sample: Record<string, unknown>;
  }> = [
    {
      name: "RawIngestV1",
      schema: "raw_ingest.v1.schema.json",
      sample: SAMPLE_RAW_INGEST as unknown as Record<string, unknown>,
    },
    {
      name: "MerkleLeafV1",
      schema: "merkle_leaf.v1.schema.json",
      sample: SAMPLE_MERKLE_LEAF as unknown as Record<string, unknown>,
    },
    {
      name: "ExtractionEnvelope",
      schema: "extraction_envelope.schema.json",
      sample: SAMPLE_EXTRACTION_ENVELOPE as unknown as Record<string, unknown>,
    },
    {
      name: "ReviewQueueV1",
      schema: "review_queue.v1.schema.json",
      sample: SAMPLE_REVIEW_QUEUE as unknown as Record<string, unknown>,
    },
    {
      name: "PackLifecycleV1",
      schema: "pack_lifecycle.v1.schema.json",
      sample: SAMPLE_PACK_LIFECYCLE as unknown as Record<string, unknown>,
    },
    {
      name: "OcsfNetworkActivityV1",
      schema: "ocsf_event.v1.schema.json",
      sample: SAMPLE_OCSF_EVENT as unknown as Record<string, unknown>,
    },
    {
      name: "ErrorResponse",
      schema: "error_response.schema.json",
      sample: SAMPLE_ERROR_RESPONSE as unknown as Record<string, unknown>,
    },
  ];

  for (const { name, schema, sample } of cases) {
    describe(name, () => {
      it("validates against JSON Schema", () => {
        const ajv = createValidator();
        const schemaObj = loadSchema(schema);
        const validate = ajv.compile(schemaObj);
        const valid = validate(sample);
        if (!valid) {
          console.error(validate.errors);
        }
        expect(valid).toBe(true);
      });

      it("round-trips through JSON serialization", () => {
        const json = JSON.stringify(sample);
        const parsed = JSON.parse(json);
        expect(parsed).toEqual(sample);
      });

      it("round-trips through JSON Schema validation after deserialization", () => {
        const ajv = createValidator();
        const json = JSON.stringify(sample);
        const parsed = JSON.parse(json);
        const schemaObj = loadSchema(schema);
        const validate = ajv.compile(schemaObj);
        expect(validate(parsed)).toBe(true);
      });
    });
  }
});

describe("Schema completeness", () => {
  it("has a schema file for every expected contract", () => {
    const files = readdirSync(SCHEMA_DIR).filter((f) =>
      f.endsWith(".schema.json"),
    );
    expect(files.length).toBe(7);
  });
});
