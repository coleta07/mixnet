import socket
import struct
import logging
import random
import os
import select

from utils import send_test_packets, log_data, connect, find_info_relay_sockets

# Fonction pour gérer la connexion SOCKS5 avec le client
def handle_client(client_socket):
    info_relay_sockets = find_info_relay_sockets()

    logging.info(f"Relais disponibles : {info_relay_sockets}")
    
    # Envoyer 10 paquets de test pour vérifier la connectivité
    send_test_packets(info_relay_sockets, "10.0.0.1", "80")

    try:
        # Étape 1 : Négociation SOCKS5 avec le client
        version, n_methods = struct.unpack("!BB", client_socket.recv(2))
        methods = client_socket.recv(n_methods)

        if version != 5:
            logging.error("Version SOCKS non supportée")
            client_socket.close()
            return

        logging.info(f"Version SOCKS reçue: {version}")

        # Authentification sans mot de passe
        client_socket.sendall(struct.pack("!BB", 0x05, 0x00))

        # Étape 2 : Demande de connexion
        version, cmd, _, addr_type = struct.unpack("!BBBB", client_socket.recv(4))

        if cmd != 0x01:
            logging.error("Commande SOCKS non supportée")
            client_socket.close()
            return

        # Redirection des données du client
        while True:
            readable, _, _ = select.select([client_socket], [], [])
            
            # Si le client envoie des données
            if client_socket in readable:
                client_data = client_socket.recv(4096)
                if not client_data:
                    break  # Fin des données du client
                log_data("Received from client", client_data)

                # Diviser les données en paquets de 1092 octets et les envoyer via un relais
                for i in range(0, len(client_data), 1092):
                    packet = client_data[i:i + 1092]
                    relay_info = random.choice(info_relay_sockets)  # Choisir un relais aléatoire
                    logging.info(f"Envoi du paquet de données client à {relay_info}")
                    
                    relay_socket = connect(*relay_info)
                    if relay_socket:
                        try:
                            relay_socket.sendall(packet)  # Envoyer le paquet au relais
                            log_data(f"Sent to {relay_info}", packet)
                        finally:
                            relay_socket.close()  # Fermer la connexion avec le relais après l'envoi

    except Exception as e:
        logging.error(f"Erreur de traitement : {e}")
    finally:
        client_socket.close()

def start_socks5_proxy():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("localhost", 9000))
    server_socket.listen(5)
    logging.info("Serveur SOCKS5 en écoute sur le port 9000...")

    while True:
        client_socket, addr = server_socket.accept()
        logging.info(f"Connexion acceptée de {addr}")
        handle_client(client_socket)
