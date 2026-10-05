"""HTTP daemon and background runner for pipeline-svc."""
import contextlib
import http.server
import json
import os
import socket
import sys
import threading
import time

PORT = int(os.environ.get("PORT", "8000"))


class QuietThreadingHTTPServer(http.server.ThreadingHTTPServer):
    def handle_error(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int] | str,
    ) -> None:
        ex = sys.exception()
        if isinstance(ex, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def handle(self) -> None:
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            super().handle()

    def finish(self) -> None:
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            super().finish()

    def do_GET(self) -> None:
        try:
            if self.path == "/health":
                body = b'{"status": "healthy", "service": "pipeline-svc"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            elif self.path.startswith("/raw"):
                import re
                from pathlib import Path
                from urllib.parse import parse_qs, urlparse

                from pipeline_svc.worker import decompress_zstd_bytes

                query = parse_qs(urlparse(self.path).query)
                pointer = query.get("pointer", [None])[0]
                if not pointer:
                    self.send_response(400)
                    self.end_headers()
                    return

                m = re.match(r"^raw_store://([^/]+)/(offset_\d+)$", pointer)
                if not m:
                    self.send_response(400)
                    self.end_headers()
                    return

                chunk_id, offset_key = m.group(1), m.group(2)
                raw_dir = Path(os.environ.get("DATA_DIR", "")) / "raw_store" if os.environ.get("DATA_DIR") else (
                    Path("/app/data/raw_store") if Path("/app/data/raw_store").exists() else Path("data/raw_store")
                )
                idx_file = raw_dir / f"{chunk_id}.idx.json"
                zst_file = raw_dir / f"{chunk_id}.zst"

                if not idx_file.exists() or not zst_file.exists():
                    self.send_response(404)
                    self.end_headers()
                    return

                idx_data = json.loads(idx_file.read_text(encoding="utf-8"))
                entry = idx_data.get("entries", {}).get(offset_key)
                if not entry:
                    self.send_response(404)
                    self.end_headers()
                    return

                decomp = decompress_zstd_bytes(zst_file.read_bytes())
                off = int(entry["offset"])
                length = int(entry["length"])
                raw_bytes = decomp[off:off + length]

                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(raw_bytes)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw_bytes)
            else:
                self.send_response(404)
                self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                err_b = str(e).encode()
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(err_b)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(err_b)
            except Exception:
                pass

    def do_POST(self) -> None:
        try:
            if self.path == "/process":
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length > 0 else b"{}"
                data = json.loads(body.decode("utf-8")) if body else {}
                lineage_ids = data.get("lineage_ids")
                with _process_lock:
                    from pipeline_svc.worker import process_events
                    res = process_events(lineage_ids=lineage_ids)
                out_b = json.dumps(res).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out_b)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(out_b)
            elif self.path == "/onboard":
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length > 0 else b"{}"
                data = json.loads(body.decode("utf-8")) if body else {}
                cluster_id = data.get("cluster_id")
                if not isinstance(cluster_id, str) or not cluster_id:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Connection", "close")
                    err_b = b'{"error": "Missing or invalid cluster_id"}'
                    self.send_header("Content-Length", str(len(err_b)))
                    self.end_headers()
                    self.wfile.write(err_b)
                    return

                actor = data.get("actor", "analyst")
                confirmed_mapping = data.get("confirmed_mapping") or data.get("overrides")
                with _process_lock:
                    from pipeline_svc.worker import onboard_cluster
                    res = onboard_cluster(
                        cluster_id=cluster_id,
                        actor=actor,
                        confirmed_mapping=confirmed_mapping,
                    )
                out_b = json.dumps(res).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out_b)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(out_b)
            else:
                self.send_response(404)
                self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                import traceback
                traceback.print_exc()
                err_b = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_b)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(err_b)
            except Exception:
                pass

    def log_message(self, format: str, *args: object) -> None:
        pass


_process_lock = threading.Lock()


def _background_worker_loop() -> None:
    """Continuously processes unextracted events from raw_events in real time."""
    time.sleep(1.0)
    while True:
        processed_any = False
        try:
            if _process_lock.acquire(blocking=False):
                try:
                    from pipeline_svc.worker import process_events
                    res = process_events(batch_limit=2000)
                    cnt = res.get("processed_count", 0)
                    if cnt > 0:
                        processed_any = True
                        print(f"[PIPELINE-DAEMON] Real-time engine auto-processed {cnt} event(s)", flush=True)
                finally:
                    _process_lock.release()
        except Exception:
            pass

        # If we had events, immediately loop to drain backlog; otherwise sleep briefly
        if not processed_any:
            time.sleep(0.2)


def main() -> None:
    print(f"pipeline-svc daemon starting on port {PORT}...")
    worker_thread = threading.Thread(target=_background_worker_loop, daemon=True)
    worker_thread.start()

    server = QuietThreadingHTTPServer(("0.0.0.0", PORT), HealthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        sys.exit(0)


if __name__ == "__main__":
    main()
