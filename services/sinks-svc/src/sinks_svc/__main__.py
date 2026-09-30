"""Entrypoint and HTTP daemon for sinks_svc package execution."""
import http.server
import json
import os
import sys
from sinks_svc.service import SinksService

PORT = int(os.environ.get("PORT", "8001"))
DATA_DIR = os.environ.get("DATA_DIR", "data")


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "sinks-svc"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    print(f"sinks-svc starting with DATA_DIR={DATA_DIR}...")
    service = SinksService(base_dir=DATA_DIR)
    service.start_background_workers()
    print(f"sinks-svc daemon listening on port {PORT}...")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), HealthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        service.stop_background_workers()
        server.server_close()
        sys.exit(0)


if __name__ == "__main__":
    main()
