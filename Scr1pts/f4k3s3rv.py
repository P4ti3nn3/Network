#!/usr/bin/env python3 

from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        response_data_json = '{"XX":"XX"}'
        response_data = json.loads(response_data_json)
        tab = [response_data]
        self.wfile.write(json.dumps(tab).encode('utf-8'))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._set_headers()
        print(post_data.decode('utf-8'))
        # Respond with a JSON containing "XX" equal to "XX"
        response_data = '{"XX":"XX", "mesage": "POST request received", "data_received": post_data.decode("utf-8")}'
        response_data = json.loads(response_data_json)
        tab = [response_data]
        self.wfile.write(json.dumps(tab).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=6673):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
