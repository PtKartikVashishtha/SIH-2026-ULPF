/**
 * integrity-svc — C2: Merkle batching, hash-chained signed ledger, anchoring, deep verification.
 */

export * from "./types.js";
export * from "./crypto.js";
export * from "./merkle.js";
export * from "./ledger.js";
export * from "./db.js";
export * from "./anchor.js";
export * from "./deep_verify.js";
export * from "./tamper_drill.js";

import http from "node:http";

export function startIntegrityDaemon(port = parseInt(process.env.PORT || "5143", 10)): http.Server {
  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "healthy", service: "integrity-svc" }));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    }
  });

  server.listen(port, "0.0.0.0", () => {
    console.log(`integrity-svc listening on port ${port}`);
  });

  return server;
}

startIntegrityDaemon();
