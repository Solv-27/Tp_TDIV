import socket
import argparse
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff

# Función para enviar una consulta DNS al servidor remoto y obtener la respuesta
def send_dns_query(query_data, dns_server, dns_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query_data, (dns_server, dns_port))
        response, _ = sock.recvfrom(4096)
    return response

# Función para manipular las consultas DNS entrantes
def handle_dns_query(data, addr, dns_server, dns_port):
    response_data = send_dns_query(data, dns_server, dns_port)
    sock.sendto(response_data, addr)

# Analizar argumentos de línea de comandos
parser = argparse.ArgumentParser(description='Servidor DNS Proxy')
parser.add_argument('-s', '--server', required=True, help='Servidor DNS remoto')
parser.add_argument('-p', '--port', type=int, help='Puerto de escucha del servidor DNS proxy')
args = parser.parse_args()

# Obtener el servidor DNS remoto y el puerto de escucha del argumento
DNS_SERVER = args.server
LISTEN_PORT = args.port if args.port else 53

# Crear socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', LISTEN_PORT))

print(f'Servidor DNS proxy en funcionamiento en el puerto {LISTEN_PORT}...')
print(f'Servidor DNS remoto: {DNS_SERVER}')

while True:
    # Esperar a recibir una consulta DNS
    data, addr = sock.recvfrom(1024)
    print('Consulta recibida desde', addr)

    # Reenviar la consulta al servidor DNS remoto
    handle_dns_query(data, addr, DNS_SERVER, LISTEN_PORT)

sock.close()
