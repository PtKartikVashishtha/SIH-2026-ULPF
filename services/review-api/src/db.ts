import Database from "better-sqlite3";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dir = dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || join(__dir, "..", "..", "..", "ulpf.db");

let _db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (_db) return _db;
  _db = new Database(DB_PATH);
  _db.pragma("journal_mode = WAL");
  _db.pragma("foreign_keys = ON");
  ensureSchema(_db);
  seedIfEmpty(_db);
  return _db;
}

function ensureSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS raw_events (
      lineage_id TEXT PRIMARY KEY, sha256_hash TEXT NOT NULL,
      ingestion_timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
      source_port INTEGER NOT NULL,
      transport_protocol TEXT NOT NULL CHECK (transport_protocol IN ('UDP','TCP','TLS','HTTP')),
      char_encoding TEXT NOT NULL, raw_size_bytes INTEGER NOT NULL,
      storage_pointer TEXT NOT NULL, chunk_id TEXT, merkle_leaf_index INTEGER, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS merkle_chunks (
      chunk_id TEXT PRIMARY KEY, event_count INTEGER NOT NULL,
      merkle_root_hash TEXT NOT NULL, batch_opened_at TEXT NOT NULL,
      batch_closed_at TEXT NOT NULL, chain_tx_hash TEXT, chain_block_id TEXT,
      anchor_status TEXT NOT NULL DEFAULT 'pending' CHECK (anchor_status IN ('pending','anchored','failed')),
      anchored_at TEXT
    );
    CREATE TABLE IF NOT EXISTS extraction_history (
      extraction_id INTEGER PRIMARY KEY AUTOINCREMENT, lineage_id TEXT NOT NULL,
      path_taken TEXT NOT NULL CHECK (path_taken IN ('HOT','COLD')),
      source_type TEXT NOT NULL, parser_version TEXT NOT NULL,
      extracted_fields TEXT NOT NULL, confidence_scores TEXT NOT NULL, processed_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS review_queue (
      review_id INTEGER PRIMARY KEY AUTOINCREMENT, lineage_id TEXT NOT NULL,
      extraction_id INTEGER NOT NULL, candidate_mapping TEXT NOT NULL,
      cluster_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_review','confirmed','rejected')),
      assigned_analyst TEXT, confirmed_mapping TEXT, created_at TEXT NOT NULL, resolved_at TEXT,
      sample_raw_pointer TEXT NOT NULL DEFAULT 'raw_store://unknown/offset_0'
    );
    CREATE INDEX IF NOT EXISTS idx_rq_cluster ON review_queue(cluster_id);
    CREATE TABLE IF NOT EXISTS mapping_packs (
      pack_id TEXT PRIMARY KEY, source_type TEXT NOT NULL, version TEXT NOT NULL,
      pack_yaml_hash TEXT NOT NULL, signature TEXT NOT NULL, signer_key_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','staged','quarantined','active','deprecated')),
      parent_pack_id TEXT REFERENCES mapping_packs(pack_id),
      chain_provenance_tx TEXT, created_at TEXT NOT NULL, promoted_at TEXT
    );
    CREATE TABLE IF NOT EXISTS pack_lifecycle_events (
      event_id INTEGER PRIMARY KEY AUTOINCREMENT, pack_id TEXT NOT NULL REFERENCES mapping_packs(pack_id),
      event_type TEXT NOT NULL CHECK (event_type IN ('pack_created','pack_confirmed','pack_updated','pack_rolled_back','pack_quarantined')),
      actor TEXT NOT NULL, event_hash TEXT NOT NULL, chain_tx_hash TEXT, occurred_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS normalization_history (
      normalization_id INTEGER PRIMARY KEY AUTOINCREMENT,
      lineage_id TEXT NOT NULL REFERENCES raw_events(lineage_id),
      extraction_id INTEGER NOT NULL REFERENCES extraction_history(extraction_id),
      ocsf_class_uid INTEGER NOT NULL,
      ocsf_event_json TEXT NOT NULL,
      schema_valid INTEGER NOT NULL,
      validation_errors TEXT,
      published_to_bus INTEGER NOT NULL DEFAULT 0,
      normalized_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS test_fixtures (
      fixture_id INTEGER PRIMARY KEY AUTOINCREMENT, pack_id TEXT NOT NULL REFERENCES mapping_packs(pack_id),
      sample_raw_pointer TEXT NOT NULL, expected_ocsf_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_eh_lineage ON extraction_history(lineage_id);
    CREATE INDEX IF NOT EXISTS idx_rq_lineage ON review_queue(lineage_id);
    CREATE INDEX IF NOT EXISTS idx_rq_ext_id ON review_queue(extraction_id);
    CREATE INDEX IF NOT EXISTS idx_nh_lineage ON normalization_history(lineage_id);
    CREATE INDEX IF NOT EXISTS idx_nh_ext_id ON normalization_history(extraction_id);
  `);
}

function ago(minutes: number): string {
  return new Date(Date.now() - minutes * 60000).toISOString();
}

function seedIfEmpty(db: Database.Database): void {
  const row = db.prepare("SELECT COUNT(*) as c FROM review_queue").get() as { c: number };
  if (row.c > 0) return;

  const insRaw = db.prepare(
    "INSERT OR IGNORE INTO raw_events (lineage_id,sha256_hash,ingestion_timestamp,source_ip,source_port,transport_protocol,char_encoding,raw_size_bytes,storage_pointer,chunk_id,merkle_leaf_index,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  );
  const raw: Array<[string,string,string,number,string,number,string,number]> = [
    ["11111111-0000-4000-a000-000000000001","c959385bbbe6a9f5becc5ad8434ab7c149e3610c9c7cf5e1741d4a2be8135826","192.168.1.100",51001,"UDP",412,"chunk_20260926_01",0],
    ["11111111-0000-4000-a000-000000000002","dc7ffd3fe0098832da9cfa609d0d6e25b8bced53c413f295b6ce929d5fe9f43f","192.168.1.101",51002,"UDP",398,"chunk_20260926_01",1],
    ["22222222-0000-4000-a000-000000000001","10a5e146d427cf514e431a3044ae32a07caa679ef10dce7d828d749550313727","10.0.0.55",514,"TCP",287,"chunk_20260926_01",2],
    ["22222222-0000-4000-a000-000000000002","d9ee46deb091227c69b3e0da8dbd7a427330c68ceda447193e3a2cb7056d19ca","10.0.0.55",514,"TCP",312,"chunk_20260926_01",3],
    ["33333333-0000-4000-a000-000000000001","c04c17110a0b22584ce622217c68be4c31c1efed253d2a6683dbc60edfdaddf8","172.16.0.10",8080,"HTTP",956,"chunk_20260926_02",0],
    ["44444444-0000-4000-a000-000000000001","8ef9b62649037825570bc32ab95e96bd516da68df4774a01c773ace5bfd6a620","10.10.1.200",443,"TLS",1204,"chunk_20260926_02",1],
  ];
  for (const [lid,sha,sip,sport,tp,sz,cid,off] of raw)
    insRaw.run(lid,sha,ago(120),sip,sport,tp,"UTF-8",sz,`raw_store://${cid}/offset_${off}`,cid,off,ago(120));

  const insExt = db.prepare(
    "INSERT INTO extraction_history (lineage_id,path_taken,source_type,parser_version,extracted_fields,confidence_scores,processed_at) VALUES (?,'COLD',?,?,?,?,?)"
  );
  type ExtRow = [string,string,object,object,number];
  const exts: ExtRow[] = [
    ["11111111-0000-4000-a000-000000000001","palo_alto_fw",{action:"deny",src_ip:"192.168.1.100",dst_ip:"8.8.8.8",dst_port:"443",protocol:"tcp",rule:"block-external"},{action:0.78,src_ip:0.92,dst_ip:0.91,dst_port:0.88,protocol:0.82,rule:0.65},110],
    ["11111111-0000-4000-a000-000000000002","palo_alto_fw",{action:"allow",src_ip:"192.168.1.101",dst_ip:"1.1.1.1",dst_port:"80",protocol:"tcp",rule:"allow-web"},{action:0.78,src_ip:0.91,dst_ip:0.90,dst_port:0.87,protocol:0.81,rule:0.64},108],
    ["22222222-0000-4000-a000-000000000001","fortinet_fortigate",{logtype:"traffic",srcip:"10.0.0.55",dstip:"203.0.113.5",action:"blocked",duration:"0"},{logtype:0.61,srcip:0.84,dstip:0.83,action:0.72,duration:0.55},90],
    ["22222222-0000-4000-a000-000000000002","fortinet_fortigate",{logtype:"traffic",srcip:"10.0.0.55",dstip:"198.51.100.7",action:"accepted",duration:"12"},{logtype:0.60,srcip:0.83,dstip:0.82,action:0.71,duration:0.54},88],
    ["33333333-0000-4000-a000-000000000001","nginx_access",{remote_addr:"172.16.0.10",request:"GET /api/v1/health HTTP/1.1",status:"200",bytes_sent:"1234",http_user_agent:"curl/7.81.0"},{remote_addr:0.88,request:0.74,status:0.69,bytes_sent:0.62,http_user_agent:0.58},60],
    ["44444444-0000-4000-a000-000000000001","windows_event",{EventID:"4624",SubjectUserName:"SYSTEM",TargetUserName:"jdoe",LogonType:"3",IpAddress:"10.10.1.200",WorkstationName:"WS-42"},{EventID:0.91,SubjectUserName:0.76,TargetUserName:0.77,LogonType:0.72,IpAddress:0.85,WorkstationName:0.68},30],
  ];
  const extIds: number[] = [];
  for (const [lid,st,ef,cs,mins] of exts) {
    const r = insExt.run(lid,st,"0.0.0",JSON.stringify(ef),JSON.stringify(cs),ago(mins));
    extIds.push(r.lastInsertRowid as number);
  }

  const insRQ = db.prepare(
    "INSERT INTO review_queue (lineage_id,extraction_id,candidate_mapping,cluster_id,status,assigned_analyst,confirmed_mapping,created_at,resolved_at,sample_raw_pointer) VALUES (?,?,?,?,?,?,?,?,?,?)"
  );
  const cm1 = {action:{candidate_ocsf_attribute:"activity_name",similarity_score:0.78,alternate_candidates:[{attribute:"disposition",similarity_score:0.65}]},src_ip:{candidate_ocsf_attribute:"src_endpoint.ip",similarity_score:0.92,alternate_candidates:[]},dst_ip:{candidate_ocsf_attribute:"dst_endpoint.ip",similarity_score:0.91,alternate_candidates:[]},dst_port:{candidate_ocsf_attribute:"dst_endpoint.port",similarity_score:0.88,alternate_candidates:[]},protocol:{candidate_ocsf_attribute:"connection_info.protocol_name",similarity_score:0.82,alternate_candidates:[]},rule:{candidate_ocsf_attribute:"firewall_rule.name",similarity_score:0.65,alternate_candidates:[{attribute:"policy.name",similarity_score:0.58}]}};
  const cm2 = {logtype:{candidate_ocsf_attribute:"type_name",similarity_score:0.61,alternate_candidates:[{attribute:"class_name",similarity_score:0.55}]},srcip:{candidate_ocsf_attribute:"src_endpoint.ip",similarity_score:0.84,alternate_candidates:[]},dstip:{candidate_ocsf_attribute:"dst_endpoint.ip",similarity_score:0.83,alternate_candidates:[]},action:{candidate_ocsf_attribute:"activity_name",similarity_score:0.72,alternate_candidates:[]},duration:{candidate_ocsf_attribute:"connection_info.session.duration",similarity_score:0.55,alternate_candidates:[]}};
  const cm3 = {remote_addr:{candidate_ocsf_attribute:"src_endpoint.ip",similarity_score:0.88,alternate_candidates:[]},request:{candidate_ocsf_attribute:"http_request.url.path",similarity_score:0.74,alternate_candidates:[{attribute:"http_request.url.text",similarity_score:0.68}]},status:{candidate_ocsf_attribute:"http_response.code",similarity_score:0.69,alternate_candidates:[]},bytes_sent:{candidate_ocsf_attribute:"traffic.bytes_out",similarity_score:0.62,alternate_candidates:[]},http_user_agent:{candidate_ocsf_attribute:"http_request.user_agent",similarity_score:0.58,alternate_candidates:[]}};
  const cm4 = {EventID:{candidate_ocsf_attribute:"type_uid",similarity_score:0.91,alternate_candidates:[]},SubjectUserName:{candidate_ocsf_attribute:"actor.user.name",similarity_score:0.76,alternate_candidates:[]},TargetUserName:{candidate_ocsf_attribute:"user.name",similarity_score:0.77,alternate_candidates:[]},LogonType:{candidate_ocsf_attribute:"logon_type_id",similarity_score:0.72,alternate_candidates:[]},IpAddress:{candidate_ocsf_attribute:"src_endpoint.ip",similarity_score:0.85,alternate_candidates:[]}};
  insRQ.run("11111111-0000-4000-a000-000000000001",extIds[0],JSON.stringify(cm1),"drain-cluster-0001","pending",null,null,ago(110),null,"raw_store://chunk_20260926_01/offset_0");
  insRQ.run("11111111-0000-4000-a000-000000000002",extIds[1],JSON.stringify(cm1),"drain-cluster-0001","pending",null,null,ago(108),null,"raw_store://chunk_20260926_01/offset_1");
  insRQ.run("22222222-0000-4000-a000-000000000001",extIds[2],JSON.stringify(cm2),"drain-cluster-0002","in_review","analyst:jdoe",null,ago(90),null,"raw_store://chunk_20260926_01/offset_2");
  insRQ.run("22222222-0000-4000-a000-000000000002",extIds[3],JSON.stringify(cm2),"drain-cluster-0002","in_review","analyst:jdoe",null,ago(88),null,"raw_store://chunk_20260926_01/offset_3");
  insRQ.run("33333333-0000-4000-a000-000000000001",extIds[4],JSON.stringify(cm3),"drain-cluster-0003","pending",null,null,ago(60),null,"raw_store://chunk_20260926_02/offset_0");
  insRQ.run("44444444-0000-4000-a000-000000000001",extIds[5],JSON.stringify(cm4),"drain-cluster-0004","confirmed","analyst:jdoe",JSON.stringify(cm4),ago(30),ago(10),"raw_store://chunk_20260926_02/offset_1");

  const insPack = db.prepare(
    "INSERT OR IGNORE INTO mapping_packs (pack_id,source_type,version,pack_yaml_hash,signature,signer_key_id,status,created_at,promoted_at) VALUES (?,?,?,?,?,?,?,?,?)"
  );
  insPack.run("cisco_asa_v1.3.0","cisco_asa","1.3.0","f4bb3623e6b7bee536fa21648d290f56fee16e01e81819eb2123859133c424c3","dc4604eef84220798f47044605719a3c9b88e14620f340809b0b4bce36cba4b54e386928e4697ff92095fefb3d4f4007a39d48692f03f757f49f493774614e04","dev-key-001","active",ago(500),ago(480));
  insPack.run("palo_alto_fw_v0.1.0","palo_alto_fw","0.1.0","31ea469be4e34629012a48f650d88acb088f1cd4f083016d4b2cc9efb6afa0c9","a9b25c6af00f3c1fb7b41d92a0363f443306db7ecdbfc6ad650059d3a01ba26654be0027f673081e7d01306e1217e9feaa5f48ce833cf51639c0d7507300f90c","dev-key-001","draft",ago(120),null);
  insPack.run("fortinet_fortigate_v0.1.0","fortinet_fortigate","0.1.0","7a91d225d9f020a37ca0582dbd29bc5607a1145699b46a6ccc744d49a3a60fd1","7211756cb1af960527084beb9ee1029cb32efc084f09d29ef1b3d0cf3bba2cf4e1e8cf0bbd6006e87f8aa89c6295ec7fe8a32a68b598d1a12a52dfdb0dcf6f01","dev-key-001","staged",ago(90),null);
  insPack.run("nginx_access_v0.1.0","nginx_access","0.1.0","3e3dcfe36749cea3bcfeebdeb02fbb99e97dad5fc0e577b076f60ed1c2bcd902","07891b40e6ff3b22c47f6a671a6ffeeae7f9999a0928236aafe7344795b5463f6ae8f921fa40df8276f57e53f191f4ae8b74659f81665a3b75a6c117b8ee830f","dev-key-001","draft",ago(60),null);
  insPack.run("windows_event_v1.0.0","windows_event","1.0.0","8de9e01b10f47ecf295774cec992855d548831cea5f5a8be58e422ac5a91e656","25f5a24ba37c19375131e5bb44ec07da85b19e917d29ae6bb580665df063e5e495254199c9c43d2621743a41b212f3e820ef69a8449c25633842c8d234dc3801","dev-key-001","active",ago(200),ago(190));

  const insLc = db.prepare("INSERT INTO pack_lifecycle_events (pack_id,event_type,actor,event_hash,occurred_at) VALUES (?,?,?,?,?)");
  insLc.run("cisco_asa_v1.3.0","pack_created","system:auto-onboarding","hash-asa-1",ago(500));
  insLc.run("cisco_asa_v1.3.0","pack_confirmed","analyst:jdoe","hash-asa-2",ago(495));
  insLc.run("palo_alto_fw_v0.1.0","pack_created","system:auto-onboarding","hash-pa-1",ago(120));
  insLc.run("fortinet_fortigate_v0.1.0","pack_created","system:auto-onboarding","hash-fg-1",ago(90));
  insLc.run("windows_event_v1.0.0","pack_created","system:auto-onboarding","hash-we-1",ago(200));
  insLc.run("windows_event_v1.0.0","pack_confirmed","analyst:admin","hash-we-2",ago(195));

  const insChunk = db.prepare(
    "INSERT OR IGNORE INTO merkle_chunks (chunk_id,event_count,merkle_root_hash,batch_opened_at,batch_closed_at,anchor_status,anchored_at) VALUES (?,?,?,?,?,?,?)"
  );
  insChunk.run("chunk_20260926_01",4,"4a8b792193b2a597a8d0554db221bc391f6920f0e21a221f57e62a1dc32f8901",ago(125),ago(120),"anchored",ago(115));
  insChunk.run("chunk_20260926_02",2,"9c21b369e802a4bf473d09a74421b8c1f09230a1e45b128f73e51a2dc84f9102",ago(65),ago(60),"pending",null);
  console.log("✓ Seed data inserted");
}
