import socket
import logging
import struct

from utils import connect, parse_packet, write_relay_info, create_relay_listener_socket, PAQUET_SIZE, PAQUET_HEADER_SIZE

def relay(relay_socket):
    # Attendre des données du client
    client_data = relay_socket.recv(PAQUET_SIZE)
    
    if not client_data:
        logging.error("No data received from client, closing connection.")
        relay_socket.close()
        return
    
    logging.info(f"Received data from client: {client_data[:PAQUET_HEADER_SIZE]}")
    layer, address_dest, port_dest = parse_packet(client_data)
    
    strip_data = client_data[PAQUET_HEADER_SIZE:]
    server_socket = connect(address_dest, port_dest)
    
    if server_socket is None:
        # Si la connexion échoue, fermer le relay_socket et enregistrer une erreur
        relay_socket.close()
        logging.error("Failed to connect to server, closing relay connection.")
        return

    logging.info("Relay connected to server")
    server_socket.sendall(strip_data)  # Envoyer le paquet

    # Fermer les connexions
    server_socket.close()
    relay_socket.close()
    logging.info("Connections closed after sending packet.")

def main_relay(address, layer):
    write_relay_info(address, 80, layer)
    server_socket = create_relay_listener_socket(address, 80)
    
    while True:
        relay_socket, addr = server_socket.accept()
        logging.info(f"Connection accepted from {addr}")
        relay(relay_socket)
