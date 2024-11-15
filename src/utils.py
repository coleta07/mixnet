import logging
import random
import socket
import os
import datetime

PAQUET_SIZE = 1092
PAQUET_HEADER_SIZE = 28
PAQUET_NUMBER = 1

# Configuration du logger
logging.basicConfig(filename="socks5_proxy.log", 
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Fonction pour enregistrer les données en hexadécimal
def log_data(label, data):
    hex_data = " ".join(f"{byte:02x}" for byte in data)
    logging.info(f"{label}: {hex_data}")

def parse_packet(packet):
    # Extraire l'adresse IP, le port et le numéro de paquet à partir de l'en-tête
    layer = int(packet[:4].decode('utf-8').rstrip('\x00'))  # Numéro de couche (4 octets, sans les zéros de padding)
    address = packet[4:24].decode('utf-8').rstrip('\x00')  # Adresse IP (20 octets, sans les zéros de padding)
    port = int(packet[24:28].decode('utf-8').rstrip('\x00'))  # Port (4 octets, sans les zéros de padding)
    logging.info(f"Destination address: {address}, port: {port}")
    return layer, address, port

def add_packet_header(data, relay_path_info, address_dest, port_dest, flags, number):

    """Ajoute un en-tête au paquet avec l'adresse de destination, le port et le numéro de paquet."""
    
    layer_header = str(relay_path_info[1][2]).encode('utf-8').ljust(4, b'\x00')
    address_header = relay_path_info[1][0].encode('utf-8').ljust(20, b'\x00')  # Adresse de destination (20 octets)
    port_header = str(relay_path_info[1][1]).encode('utf-8').ljust(4, b'\x00')
    packet_header = layer_header + address_header + port_header
    layer_header = str(relay_path_info[2][2]).encode('utf-8').ljust(4, b'\x00')
    address_header = relay_path_info[2][0].encode('utf-8').ljust(20, b'\x00')  # Adresse de destination (20 octets)
    port_header = str(relay_path_info[2][1]).encode('utf-8').ljust(4, b'\x00')
    packet_header += layer_header + address_header + port_header
    layer_header = str(1).encode('utf-8').ljust(4, b'\x00')
    address_header = address_dest.encode('utf-8').ljust(20, b'\x00')  # Adresse de destination (20 octets)
    port_header = str(port_dest).encode('utf-8').ljust(4, b'\x00')  
    packet_header += layer_header + address_header + port_header
    packet_header += str(flags).encode('utf-8').ljust(1, b'\x00')
    packet_header += number.to_bytes(1, byteorder='little')

    return packet_header + data  # Retourne le paquet complet avec l'en-tête ajouté

def connect(address, port):
    try:
        # Création d'un socket pour la connexion au serveur
        #logging.info(f"Tentative de connexion au relais {address}:{port}")
        relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # indiquer l'heure dans les logs
        relay_socket.connect((address, port))
        #logging.info(f"Connexion au relais {address}:{port} réussie")
        return relay_socket
    except Exception as e:
        logging.error(f"Erreur de connexion au relais {address}:{port} : {e}")
        return None
    
def find_info_relay_sockets():
    relay_sockets = []
    with open("../../../conf/relay_info.txt", "r") as file:
        for line in file:
            address, port, layer = line.strip().split(", ")
            relay_sockets.append((address, int(port), int(layer)))
    return relay_sockets

def write_relay_info(address, port, layer):
    with open("../../../conf/relay_info.txt", "r") as file:
        contenu = file.readlines()
    
    adresse_presente = False
    for line in contenu:
        address_file, _, _ = line.strip().split(", ")
        if address_file == address:
            adresse_presente = True
            break

    # Ajouter l'adresse si elle n'est pas présente
    if not adresse_presente:
        with open("../../../conf/relay_info.txt", "a") as file:
            file.write(f"{address}, {port}, {layer}\n")

def create_relay_listener_socket(address, port):
    """Crée et configure un socket d'écoute pour le relais."""
    relay_listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_listener_socket.bind((address, port))
    relay_listener_socket.listen(5)
    #logging.info(f"Relay listening on port {80} at IP {address}")
    return relay_listener_socket

def send_paquet_to_relay(client_data, relay_sockets, address_dest, port_dest, flags=0):
    global PAQUET_NUMBER
    for i in range(0, len(client_data),PAQUET_SIZE-PAQUET_HEADER_SIZE*3-2):
        packet = client_data[i:i + PAQUET_SIZE-PAQUET_HEADER_SIZE*3-2]
        relay_path_info = choose_path(relay_sockets)
        packet = add_packet_header(packet, relay_path_info, address_dest, port_dest, flags, PAQUET_NUMBER)
        #logging.info("packet = ", packet)
        relay_socket = connect(relay_path_info[0][0], relay_path_info[0][1])
        if flags == 0:
            if PAQUET_NUMBER == 9:
                PAQUET_NUMBER = 0
            PAQUET_NUMBER += 1

        if relay_socket:
            try:
                relay_socket.sendall(packet)
            finally:
                relay_socket.close()  # Fermer la connexion après l'envoi du paquet

def choose_path(relay_sockets):
    layer1 = []
    layer2 = []
    layer3 = []
    for info in relay_sockets:
        if info[2] == 1:
            layer1.append(info)
        elif info[2] == 2:
            layer2.append(info)
        elif info[2] == 3:
            layer3.append(info)
    return (random.choice(layer1), random.choice(layer2), random.choice(layer3))

def dummy_traffic(address_dest, port_dest, relay_sockets):
    dummy_data = os.urandom(PAQUET_SIZE - PAQUET_HEADER_SIZE*3-1)
    send_paquet_to_relay(dummy_data, relay_sockets,address_dest, port_dest, 1)
        



