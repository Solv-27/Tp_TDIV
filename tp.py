import socket
import argparse

# Función para enviar una consulta DNS al servidor remoto y obtener la respuesta
def send_dns_query(query_data, dns_server, dns_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query_data, (dns_server, dns_port))
        response, _ = sock.recvfrom(4096)
    return response

# Función para obtener la dirección IP de la respuesta DNS
def extract_ip_address(response_data):
    from dnslib import DNSRecord

    # Analizar el mensaje DNS
    dns_response = DNSRecord.parse(response_data)

    # Obtener la dirección IP de la respuesta (asumiendo que solo hay una respuesta)
    ip_address = dns_response.a.rdata if dns_response.a else None

    return ip_address

# Función para manipular las consultas DNS entrantes
def handle_dns_query(data, addr, dns_server, dns_port):
    response_data = send_dns_query(data, dns_server, dns_port)
    sock.sendto(response_data, addr)
    
    # Obtener la dirección IP de la respuesta DNS
    ip_address = extract_ip_address(response_data)
    
    # Imprimir la dirección IP
    print(ip_address)

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
    print('Consulta recibida desde', addr)

    # Reenviar la consulta al servidor DNS remoto
    if DESTINATION_DOMAIN and DESTINATION_IP:
        data = data.replace(DESTINATION_DOMAIN.encode(), DESTINATION_IP.encode())
    handle_dns_query(data, addr, DNS_SERVER, LISTEN_PORT)
    print('Respondiendo...')

sock.close()
