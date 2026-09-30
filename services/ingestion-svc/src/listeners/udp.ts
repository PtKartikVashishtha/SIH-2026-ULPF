import dgram from "node:dgram";

export function createUdpListener(options: {
  port: number;
  host?: string;
  onMessage: (msg: Buffer, rinfo: dgram.RemoteInfo) => void;
  onError?: (err: Error) => void;
}): { server: dgram.Socket; close: () => Promise<void> } {
  const socket = dgram.createSocket("udp4");

  socket.on("message", (msg, rinfo) => {
    options.onMessage(msg, rinfo);
  });

  if (options.onError) {
    socket.on("error", options.onError);
  }

  socket.bind(options.port, options.host || "0.0.0.0");

  return {
    server: socket,
    close: () =>
      new Promise((resolve) => {
        socket.close(() => resolve());
      }),
  };
}
