import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import http from "node:http";
import dgram from "node:dgram";
import net from "node:net";
import { IngestionService } from "../src/service.js";

const TEST_DIR = join(process.cwd(), "test-tmp-service");
const DB_FILE = join(TEST_DIR, "service.db");

describe("IngestionService End-to-End Listeners & Integration", () => {
  let service: IngestionService;
  const HTTP_PORT = 15142;
  const UDP_PORT = 15140;
  const TCP_PORT = 15141;

  beforeEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });

    service = new IngestionService({
      dataDir: TEST_DIR,
      dbPath: DB_FILE,
      batcherConfig: { maxEventCount: 2, maxTimeMs: 100 },
    });

    await service.startListeners({
      http: HTTP_PORT,
      udp: UDP_PORT,
      tcp: TCP_PORT,
    });
  });

  afterEach(async () => {
    await service.close();
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  it("ingests logs via HTTP listener", async () => {
    const payload = "GET /index.html HTTP/1.1 from 192.168.1.100";
    const res = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: HTTP_PORT,
          path: "/ingest",
          method: "POST",
          headers: { "Content-Type": "text/plain" },
        },
        (resp) => {
          let body = "";
          resp.on("data", (chunk) => (body += chunk));
          resp.on("end", () => resolve({ status: resp.statusCode || 0, body }));
        }
      );
      req.on("error", reject);
      req.write(payload);
      req.end();
    });

    expect(res.status).toBe(200);
    const parsed = JSON.parse(res.body);
    expect(parsed.status).toBe("accepted");
    expect(parsed.lineage_id).toBeDefined();

    // Flush batcher
    await service.flush();
    expect(service.db.countRawEvents()).toBe(1);
  });

  it("ingests logs via UDP Syslog listener", async () => {
    const udpClient = dgram.createSocket("udp4");
    const syslogMsg = Buffer.from("<34>1 2026-09-26T12:00:00Z myhost myapp - - %ASA-4-106023: Test UDP");

    await new Promise<void>((resolve) => {
      udpClient.send(syslogMsg, UDP_PORT, "127.0.0.1", () => resolve());
    });
    udpClient.close();

    // Wait for event to be processed and time trigger to flush
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(service.db.countRawEvents()).toBe(1);
  });

  it("ingests logs via TCP Syslog listener", async () => {
    const client = new net.Socket();
    await new Promise<void>((resolve) => client.connect(TCP_PORT, "127.0.0.1", () => resolve()));

    client.write("<13>1 2026-09-26T12:00:00Z router1 kernel - - Test TCP log line\n");
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
    client.end();

    // Wait for event to be processed and time trigger to flush
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(service.db.countRawEvents()).toBe(1);
  });
});
