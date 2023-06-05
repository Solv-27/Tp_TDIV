import socket
import argparse
from scapy.all import *
from scapy import *

# Función para enviar una consulta DNS al servidor remoto y obtener la respuesta
def send_dns_query(query_data, dns_server, dns_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query_data, (dns_server, dns_port))
        response, _ = sock.recvfrom(4096)
    return response

# Función para obtener la dirección IP de la respuesta DNS
def extract_ip_address(response_data):
    ip_address = None
    try:
        ip_address = socket.inet_ntoa(response_data[-4:])
    except:
        pass
    return ip_address

# Función para manipular las consultas DNS entrantes
def handle_dns_query(data, addr, dns_server, dns_port, destination_domain, destination_ip):
    # Obtener la consulta DNS
    pkt = DNS(data)
    query= pkt[DNSQR].qname.decode()
    query= query[:-1]
  

    # Obtener el nombre de dominio de la consulta
    domain = query.split()[0]

    print(f'[*] Consulta recibida: {domain} (de {addr[0]}:{addr[1]})')
    print(domain)

    if domain != destination_domain:
        
        # Enviar la consulta DNS al servidor remoto y obtener la respuesta real
        response_data = send_dns_query(data, dns_server, dns_port)
        ip_address = extract_ip_address(response_data)

        if ip_address:
            print(f'[*] Respondiendo {ip_address} (vía {dns_server})')
            # Construir la respuesta DNS con la dirección IP real
            response = f'{domain} A {ip_address}'
        else:
            print('[!] No se pudo obtener la respuesta real. Respondiendo con dirección IP predeterminada.')
            # Construir la respuesta DNS con la dirección IP predeterminada
            response = f'{domain} A {destination_ip}'
    else:

        print(f'[*] Respondiendo {destination_ip} (predeterminado)')
        # Construir la respuesta DNS con la dirección IP predeterminada
        response = f'{domain} A {destination_ip}'

    # Enviar la respuesta DNS al cliente
    sock.sendto(response.encode(), addr)

# Analizar argumentos de línea de comandos
parser = argparse.ArgumentParser(description='Servidor DNS Proxy')
parser.add_argument('-s', '--server', required=True, help='Servidor DNS remoto')
parser.add_argument('-p', '--port', type=int, help='Puerto de escucha del servidor DNS proxy')
parser.add_argument('-d', '--destination', help='Dominio y dirección IP de destino en formato "dominio:ip"')
args = parser.parse_args()

# Obtener el servidor DNS remoto y el puerto de escucha del argumento
DNS_SERVER = args.server
LISTEN_PORT = args.port if args.port else 53

# Obtener el dominio y la dirección IP de destino si se proporciona
destination = args.destination.split(':') if args.destination else ['', '']
DESTINATION_DOMAIN = destination[0]
DESTINATION_IP = destination[1] if len(destination) > 1 else ''

# Crear socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', LISTEN_PORT))

print(f'Servidor DNS proxy en funcionamiento en el puerto {LISTEN_PORT}...')
print(f'Servidor DNS remoto: {DNS_SERVER}')




while True:
    # Esperar a recibir una consulta DNS
    data, addr = sock.recvfrom(1024)

    # Manipular la consulta DNS
    handle_dns_query(data, addr, DNS_SERVER, LISTEN_PORT, DESTINATION_DOMAIN, DESTINATION_IP)
