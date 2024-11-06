import socket
import random
import logging
import select
import threading
import datetime
from utils import log_data, connect, find_info_relay_sockets, create_relay_listener_socket,send_paquet_to_relay, PAQUET_SIZE, PAQUET_HEADER_SIZE

# Fonction pour gérer la communication avec le serveur final sur le port 9000
def handle_server_final(server_socket, relay_sockets):
    try:
        # Activer le keep-alive pour maintenir la connexion vivante
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        while True:
            # Écouter les données du serveur avec un timeout de 30 secondes
            readable, _, _ = select.select([server_socket], [], [], 30)
            if server_socket in readable:
                server_data = server_socket.recv(4096)
                if not server_data:
                    break  # Fin des données du serveur final
                log_data("Received from final server", server_data)
                send_paquet_to_relay(server_data, relay_sockets, "10.0.0.2", "80")

    except Exception as e:
        logging.error(f"Erreur dans la gestion du serveur final : {e}")
    finally:
        logging.info("Fermeture de la connexion du serveur final")
        server_socket.close()

# Fonction pour gérer les connexions ponctuelles provenant des relais sur le port 80
def handle_relay_listener(server_socket):
    relay_listener_socket = create_relay_listener_socket("10.0.0.1", 81)
    
    while True:
        relay_socket, addr = relay_listener_socket.accept()
        logging.info(f"Connexion acceptée de {addr} (relais) sur le port 80")
        try:
            # Recevoir un paquet du relais et enlever les 28 premiers octets
            relay_data = relay_socket.recv(PAQUET_SIZE)
            if relay_data:
                # Transmettre les données sans l'en-tête au serveur final
                server_socket.sendall(relay_data)
                logging.info("Données du relais (sans en-tête) transmises au serveur final")
        except Exception as e:
            logging.error(f"Erreur lors de la réception depuis le relais : {e}")
        finally:
            relay_socket.close()  # Fermer la connexion après réception

# Fonction pour démarrer le serveur final local sur le port 9000 et lancer l'écoute relais sur le port 80
def start_final_server(address):
    server_socket = connect("10.0.0.10", 21)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # Obtenir les relais disponibles
    relay_sockets = find_info_relay_sockets()

    relay_thread = threading.Thread(target=handle_relay_listener, args=(server_socket,), daemon=True)
    relay_thread.start()

    # # Gérer les données envoyées par le serveur final
    handle_server_final(server_socket, relay_sockets)
    server_socket.close()