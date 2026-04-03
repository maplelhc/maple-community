#!/data/data/com.termux/files/usr/bin/python3
import http.server
import socketserver

PORT = 8084
PORT_FILE = "/data/data/com.termux/files/home/current_bore_port"

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            with open(PORT_FILE, 'r') as f:
                content = f.read().strip()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(content.encode())
        except Exception as e:
            self.send_error(500, str(e))

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
