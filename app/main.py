"""Minimal web service for the Module 2 delivery foundation.

It exists to be built, shipped and rolled back by the pipeline, not to do anything clever.
Standard library only, so the container image has no dependencies to install or patch.

Endpoints
  GET /         service name and the version baked in at build time
  GET /healthz  liveness check used by the container platform

Every request is logged as one JSON line on stdout. That is the seam the later modules attach to:
a structured record of what the service did, ready to be collected and audited.
"""

import json
import os
import signal
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE_NAME = "pe-module2-foundation"


class Handler(BaseHTTPRequestHandler):
    # Do not advertise the server software or the Python version.
    server_version = SERVICE_NAME
    sys_version = ""

    def _send_json(self, status, body, head_only=False):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)

    def _route(self):
        if self.path == "/":
            return 200, {"service": SERVICE_NAME, "version": self.server.version}
        if self.path == "/healthz":
            return 200, {"status": "ok"}
        return 404, {"error": "not found"}

    def do_GET(self):
        self._send_json(*self._route())

    def do_HEAD(self):
        # Same status and headers as GET, no body: health checkers and load balancers may use HEAD.
        self._send_json(*self._route(), head_only=True)

    def log_request(self, code="-", size="-"):
        record = {"event": "request", "method": self.command, "path": self.path, "status": int(code)}
        sys.stdout.write(json.dumps(record) + "\n")
        sys.stdout.flush()

    def log_message(self, format, *args):  # noqa: A002 - signature fixed by the base class
        # Errors from the base class go to stderr as plain text; keep them out of the JSON stream.
        sys.stderr.write("%s\n" % (format % args))


class Server(ThreadingHTTPServer):
    def server_bind(self):
        # The standard library resolves the host name here (getfqdn). Binding to 0.0.0.0, as a
        # container does, made that lookup stall for 5 seconds on a slow resolver. The name is
        # unused by this service, so bind without any DNS lookup.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def make_server(host, port, version):
    server = Server((host, port), Handler)
    server.version = version
    return server


def main():
    host = os.environ.get("HOST", "0.0.0.0")  # noqa: S104 - bind inside the container
    port = int(os.environ.get("PORT", "8080"))
    version = os.environ.get("APP_VERSION", "dev")

    with open("/tmp/started-at", "w") as fh:
        fh.write(version)

    server = make_server(host, port, version)

    # The container platform stops a task with SIGTERM: finish cleanly instead of being killed.
    def stop(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    sys.stdout.write(json.dumps({"event": "start", "version": version, "port": port}) + "\n")
    sys.stdout.flush()
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()
