import http from "node:http";

export function createHttpListener(options: {
  port: number;
  host?: string;
  onMessage: (msg: Buffer, rinfo: { address: string; port: number }) => Promise<{ lineage_id: string; sha256_hash?: string } | void>;
  onBatch?: (events: any[], rinfo: { address: string; port: number }) => Promise<Array<{ lineage_id: string; sha256_hash?: string }>>;
  onFlush?: () => Promise<void>;
  onError?: (err: Error) => void;
}): { server: http.Server; close: () => Promise<void> } {
  const server = http.createServer(async (req, res) => {
    // 1. Single Ingest endpoint
    if (req.method === "POST" && (req.url === "/ingest" || req.url === "/api/v1/ingest")) {
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", async () => {
        const body = Buffer.concat(chunks);
        const rinfo = {
          address: req.socket.remoteAddress || "127.0.0.1",
          port: req.socket.remotePort || 0,
        };
        try {
          const result = await options.onMessage(body, rinfo);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ status: "accepted", ...(result || {}) }));
        } catch (err: any) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { code: "INGESTION_ERROR", message: err.message } }));
        }
      });
    }
    // 2. Batch Ingest endpoint
    else if (req.method === "POST" && (req.url === "/ingest/batch" || req.url === "/api/v1/ingest/batch")) {
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", async () => {
        const body = Buffer.concat(chunks);
        const rinfo = {
          address: req.socket.remoteAddress || "127.0.0.1",
          port: req.socket.remotePort || 0,
        };
        try {
          let events: any[] = [];
          try {
            const parsed = JSON.parse(body.toString("utf-8"));
            if (Array.isArray(parsed)) {
              events = parsed;
            } else if (parsed && Array.isArray(parsed.events)) {
              events = parsed.events;
            } else if (parsed && typeof parsed.payload === "string") {
              events = [parsed];
            } else {
              events = [body.toString("utf-8")];
            }
          } catch {
            events = body.toString("utf-8").split(/\r?\n/).filter(line => line.trim().length > 0);
          }

          if (options.onBatch) {
            const results = await options.onBatch(events, rinfo);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "accepted", count: results.length, events: results }));
          } else {
            const results = [];
            for (const ev of events) {
              const b = Buffer.from(typeof ev === "string" ? ev : (ev.payload || JSON.stringify(ev)));
              const r = await options.onMessage(b, rinfo);
              if (r) results.push(r);
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "accepted", count: results.length, events: results }));
          }
        } catch (err: any) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { code: "INGESTION_ERROR", message: err.message } }));
        }
      });
    }
    // 3. Flush endpoint
    else if (req.method === "POST" && (req.url === "/flush" || req.url === "/api/v1/flush")) {
      try {
        if (options.onFlush) {
          await options.onFlush();
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "flushed" }));
      } catch (err: any) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { code: "FLUSH_ERROR", message: err.message } }));
      }
    }
    // 4. Health
    else if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "healthy", service: "ingestion-svc" }));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { code: "NOT_FOUND", message: "Not found" } }));
    }
  });

  if (options.onError) {
    server.on("error", options.onError);
  }

  server.listen(options.port, options.host || "0.0.0.0");

  return {
    server,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
