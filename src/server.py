import socket
import logging
import select
import threading
from collections import OrderedDict

from utils import log_data, connect, find_info_relay_sockets, create_relay_listener_socket,send_paquet_to_relay, dummy_traffic,  PAQUET_SIZE, PAQUET_HEADER_SIZE

packet_buffer = OrderedDict()
expected_packet_number = 1

# Fonction pour gérer la communication avec le serveur final sur le port 9000
def handle_server_final(server_socket, relay_sockets, address, address_dest):
    try:
        x = 0
        # Activer le keep-alive pour maintenir la connexion vivante
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        dummy_traffic(address_dest, "80", relay_sockets) # drop traffic
        dummy_traffic(address, "81", relay_sockets) # loop traffic
        while True:
            # Écouter les données du serveur avec un timeout de 30 secondes
            readable, _, _ = select.select([server_socket], [], [], 30)
            if server_socket in readable:
                server_data = server_socket.recv(4096)
                if not server_data:
                    break  # Fin des données du serveur final
                if x == 0:
                    #log_data("Received from final server", server_data)
                    x = 1
                send_paquet_to_relay(server_data, relay_sockets, address_dest, "80")

    except Exception as e:
        logging.error(f"Erreur dans la gestion du serveur final : {e}")
    finally:
        logging.info("Fermeture de la connexion du serveur final")
        server_socket.close()

# Fonction pour gérer les connexions ponctuelles provenant des relais sur le port 80
def handle_relay_listener(server_socket, address):
    relay_listener_socket = create_relay_listener_socket(address, 81)

    while True:
        relay_socket, addr = relay_listener_socket.accept()
        logging.info(f"Connexion acceptée de {addr} (relais) sur le port 80")
        try:
            # Recevoir un paquet du relais et enlever les 28 premiers octets
            relay_data = relay_socket.recv(PAQUET_SIZE)
            if relay_data:
                strip_data = relay_data[:len(relay_data) - PAQUET_HEADER_SIZE*3]
                if (strip_data[:1] == b'0'):
                    strip_data = strip_data[1:]
                    PAQUET_NUMBER = int.from_bytes(strip_data[:1], byteorder='little')
                    strip_data = strip_data[1:]
                    packet_buffer[PAQUET_NUMBER] = strip_data
                    logging.info(f"Paquet {PAQUET_NUMBER} ajouté au buffer")
                    send_paquet_in_order(server_socket)
                    #log_data("Données du relais (sans en-tête) transmises au serveur final : ", strip_data)
        except Exception as e:
            logging.error(f"Erreur lors de la réception depuis le relais : {e}")
        finally:
            relay_socket.close()  # Fermer la connexion après réception

def send_paquet_in_order(server_socket):
    global expected_packet_number
    
    while expected_packet_number in packet_buffer:
        # Envoyer le paquet attendu
        data_to_send = packet_buffer.pop(expected_packet_number)
        server_socket.sendall(data_to_send)
        logging.info(f"Paquet {expected_packet_number} envoyé au serveur")
            
        # Passer au paquet suivant
        if expected_packet_number == 9:
            expected_packet_number = 0
        expected_packet_number += 1

# Fonction pour démarrer le serveur final local sur le port 9000 et lancer l'écoute relais sur le port 80
def start_final_server(address, server_adress, address_dest):
    server_socket = connect(server_adress, 21)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # Obtenir les relais disponibles
    relay_sockets = find_info_relay_sockets()

    relay_thread = threading.Thread(target=handle_relay_listener, args=(server_socket,address), daemon=True)
    relay_thread.start()

    # # Gérer les données envoyées par le serveur final
    handle_server_final(server_socket, relay_sockets, address, address_dest)
    server_socket.close()