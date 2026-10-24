#!/usr/bin/env python3
"""The protected service of the ZTC demo.

It answers every GET and POST with the subject that ztc-pep put in the
X-ZTC-Subject header, so the demo can show who the PEP let through.

Usage: demo-upstream.py <port>
"""

import http.server
import sys


class Upstream(http.server.BaseHTTPRequestHandler):
    def answer(self):
        body_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(body_length)
        subject = self.headers.get("X-ZTC-Subject", "nobody")
        body = f"stored for {subject}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = answer
    do_POST = answer


if __name__ == "__main__":
    port = int(sys.argv[1])
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Upstream).serve_forever()
