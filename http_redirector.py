import argparse
import socket
from scapy.all import *

class HTTPServer:
    def __init__(self, redirect_map, default_content_map, default_content_path):
        self.redirect_map = redirect_map
        self.default_content_map = default_content_map
        self.default_content_path = default_content_path

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 80))
            s.listen()

            while True:
                conn, addr = s.accept()
                with conn:
                    print('Connected by', addr)

                    data = conn.recv(1024)
                    if not data:
                        continue

                    packet = IP(data)

                    if packet.haslayer(HTTP):
                        http_layer = packet[HTTP]

                        if http_layer.Method == b'GET':
                            host = http_layer.Host.decode('utf-8')

                            if host in self.redirect_map:
                                target = self.redirect_map[host]
                                print(f"[*] Request GET received (Host: {host})")
                                print(f"[*] Responding with redirection to {target}")
                                response = self.get_http_redirect_response(target)
                            else:
                                print(f"[*] Request GET received (Host: {host})")
                                response = self.get_http_not_found_response()

                            conn.sendall(raw(response))

    @staticmethod
    def get_http_redirect_response(location):
        return IP()/TCP()/HTTP()/HTTPResponse(Status_Code=301, Status_Reason='Moved Permanently',
                                              Headers={'Location': location})

    @staticmethod
    def get_http_not_found_response():
        return IP()/TCP()/HTTP()/HTTPResponse(Status_Code=404, Status_Reason='Not Found')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--redirect", action="append", nargs=1, metavar=("DOMAIN:TARGET"),
                        help="domain to target redirection")
    args = parser.parse_args()

    redirect_map = {}
    if args.redirect:
        for redirect in args.redirect:
            domain, target = redirect[0].split(":")
            redirect_map[domain] = target

    server = HTTPServer(redirect_map, set(), None)
    server.start()

