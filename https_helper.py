from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

httpd = HTTPServer(("0.0.0.0", 8443), SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("certs/cert.pem", "certs/key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("HTTPS helper running on https://0.0.0.0:8443")
httpd.serve_forever()
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

httpd = HTTPServer(("localhost", 8443), SimpleHTTPRequestHandler)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("certs/cert.pem", "certs/key.pem")

httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("HTTPS helper running on https://localhost:8443 (open in browser and accept risk)")
httpd.serve_forever()

