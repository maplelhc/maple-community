#!/data/data/com.termux/files/usr/bin/python3
import http.server
import socketserver
import os

PORT_FILE = os.path.expanduser("~/current_bore_port")
PORT = 8081  # 公告牌服务监听的端口，你可以改成其他

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/port':
            try:
                with open(PORT_FILE, 'r') as f:
                    port = f.read().strip()
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(port.encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        else:
            self.send_response(404)
            self.end_headers()

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"公告牌服务运行在 http://localhost:{PORT}/port")
    httpd.serve_forever()
