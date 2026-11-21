#!/usr/bin/env python3
"""A stand-in for the receiving app, for testing logins on a development machine.

Listens on http://localhost:9090/assets, checks the X-Asset-Delivery-Secret header, prints
each delivery and answers 204 (or 401 if the secret is wrong). Stop it with Ctrl+C.

    python3 scripts/test-receiver.py --secret CHANGE-to-a-long-random-shared-secret
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser(description="Test receiver for asset deliveries")
parser.add_argument("--secret", required=True, help="the value of app.asset-delivery.secret")
parser.add_argument("--port", type=int, default=9090)
args = parser.parse_args()


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path != "/assets":
            self.send_response(404)
        elif self.headers.get("X-Asset-Delivery-Secret") != args.secret:
            print("Refused a delivery: wrong or missing secret")
            self.send_response(401)
        else:
            delivery = json.loads(body)
            print(f"Delivery for {delivery['tenant']}/{delivery['username']} "
                  f"(role {delivery['role']}, request {delivery['requestId']}):")
            for asset in delivery["assets"]:
                print(f"    {asset['name']:<24} {asset['value']}")
            if not delivery["assets"]:
                print("    (no assets)")
            self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


print(f"Test receiver listening on http://localhost:{args.port}/assets (Ctrl+C to stop)")
HTTPServer(("127.0.0.1", args.port), Receiver).serve_forever()
