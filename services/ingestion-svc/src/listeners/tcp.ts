import net from "node:net";

export function createTcpListener(options: {
  port: number;
  host?: string;
  onMessage: (msg: Buffer, rinfo: { address: string; port: number }) => void;
  onError?: (err: Error) => void;
}): { server: net.Server; close: () => Promise<void> } {
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);

    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      // Support newline-delimited framing
      let newlineIndex: number;
      while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
        const line = buffer.subarray(0, newlineIndex);
        buffer = buffer.subarray(newlineIndex + 1);
        if (line.length > 0) {
          options.onMessage(line, {
            address: socket.remoteAddress || "127.0.0.1",
            port: socket.remotePort || 0,
          });
        }
      }
    });

    if (options.onError) {
      socket.on("error", options.onError);
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
