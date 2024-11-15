import socket
import struct
import logging
import select
import threading
from collections import OrderedDict
from utils import log_data, find_info_relay_sockets,create_relay_listener_socket, send_paquet_to_relay, dummy_traffic, PAQUET_SIZE, PAQUET_HEADER_SIZE

packet_buffer = OrderedDict()
expected_packet_number = 1

def negociate_socks5(client_socket):
    version, n_methods = struct.unpack("!BB", client_socket.recv(2))
    methods = client_socket.recv(n_methods)

    if version != 5:
        logging.error("Version SOCKS non supportée")
        client_socket.close()
        return

    # Authentification sans mot de passe
    client_socket.sendall(struct.pack("!BB", 0x05, 0x00))

    # Commande de connexion
    version, cmd, _, addr_type = struct.unpack("!BBBB", client_socket.recv(4))
    if cmd != 0x01:
        logging.error("Commande SOCKS non supportée")
        client_socket.close()
        return
    client_socket.recv(4096)  # Ignorer le champ réservé
    logging.info(f"Connexion SOCKS5 établie avec le client sur le port 9000")
    client_socket.sendall(struct.pack("!BBBBIH", 0x05, 0x00, 0x00, 0x01, 0, 0))

# Fonction pour gérer la communication avec le client local sur le port 9000
def handle_local_client(client_socket, relay_sockets, address, address_dest):
    try:
        negociate_socks5(client_socket)  # Négocier la connexion SOCKS5
        dummy_traffic(address_dest, "81", relay_sockets) # drop traffic
        dummy_traffic(address, "80", relay_sockets) # loop traffic
        # Boucle de communication avec le client local
        while True:
            readable, _, _ = select.select([client_socket], [], [])
            if client_socket in readable:
                client_data = client_socket.recv(4096)
                if not client_data:
                    break  # Fin des données du client
                log_data("Received from client", client_data)
                send_paquet_to_relay(client_data, relay_sockets, address_dest, "81")
                
    except Exception as e:
        logging.error(f"Erreur dans le traitement du client local : {e}")
    finally:
        logging.info("Fermeture de la connexion du client local")
        client_socket.close()

# Fonction pour gérer les connexions ponctuelles provenant de l'extérieur sur le port 80
def handle_external_listener(client_socket):

    server_socket = create_relay_listener_socket("0.0.0.0", 80)
    while True:
        # Accepter la connexion externe
        external_socket, addr = server_socket.accept()
        logging.info(f"Connexion acceptée de {addr} sur le port 80")
        
        try:
            # Recevoir un paquet et le transmettre au client local
            external_data = external_socket.recv(PAQUET_SIZE)
            if external_data:
                if (external_data[:1] == b'0'):
                    strip_data = external_data[:len(external_data) - PAQUET_HEADER_SIZE*3]
                    strip_data = strip_data[1:]
                    PAQUET_NUMBER = int.from_bytes(strip_data[:1], byteorder='little')
                    strip_data = strip_data[1:]
                    packet_buffer[PAQUET_NUMBER] = strip_data
                    logging.info(f"Paquet {PAQUET_NUMBER} ajouté au buffer")
                    send_paquet_in_order(client_socket)
        except Exception as e:
            logging.error(f"Erreur lors du traitement de la connexion externe : {e}")
        finally:
            external_socket.close()  # Fermer la connexion après avoir reçu le paquet

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

# Fonction pour démarrer le serveur SOCKS5 local sur le port 9000
def start_local_socks5_proxy(address, address_dest):
    server_socket = create_relay_listener_socket("localhost", 9000)

    # Accepter une seule connexion du client local
    client_socket, addr = server_socket.accept()
    logging.info(f"Connexion acceptée de {addr} (client local sur le port 9000)")
    relay_sockets = find_info_relay_sockets()  # Charger les relais disponibles
    
    # Lancer le thread pour gérer les données externes sur le port 80
    external_thread = threading.Thread(target=handle_external_listener, args=(client_socket,), daemon=True)
    external_thread.start()
    
    # Traiter les données envoyées par le client local
    handle_local_client(client_socket, relay_sockets, address, address_dest)
