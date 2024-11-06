import socket
import struct
import logging
import select
import random  # Import pour la sélection aléatoire

# Configuration du logger
logging.basicConfig(filename="socks5_proxy.log", 
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Fonction pour enregistrer les données en hexadécimal
def log_data(label, data):
    hex_data = " ".join(f"{byte:02x}" for byte in data)
    logging.info(f"{label}: {hex_data}")

# Fonction pour gérer la connexion SOCKS5 avec le client
def handle_client(client_socket):
    info_relay_sockets = [("relay1", 80)]
    relay_sockets = []
    for relay_name, relay_port in info_relay_sockets:
        relay_socket = connect_to_relay(relay_name, relay_port)
        if relay_socket is None:
            for relay_socket in relay_sockets:
                relay_socket.close()
            client_socket.close()
            return
        relay_sockets.append(relay_socket)
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

        
        # Redirection des données
        while True:
            # Vérifier si des données sont prêtes dans le client_socket ou les relay_sockets
            relays = relay_sockets.copy()
            relays.append(client_socket)
            readable, _, _ = select.select(relays, [], [])
            
            # Si le client envoie des données
            if client_socket in readable:
                client_data = client_socket.recv(4096)
                if not client_data:
                    break  # Fin des données du client
                log_data("Received from client", client_data)

                # Diviser les données en paquets de 1092 octets et les envoyer via un relais aléatoire
                for i in range(0, len(client_data), 1092):
                    packet = client_data[i:i + 1092]
                    selected_relay = random.choice(relay_sockets)
                    selected_relay.sendall(packet)  # Envoyer le paquet au relais sélectionné
                    log_data(f"Sent to {selected_relay.getpeername()}", packet)

            # Si un relais envoie des données
            for relay_socket in relay_sockets:
                if relay_socket in readable:
                    relay_data = relay_socket.recv(4096)
                    if not relay_data:
                        break  # Fin des données du relais
                    log_data("Received from relay", relay_data)
                    client_socket.sendall(relay_data)  # Envoyer au client

    except Exception as e:
        logging.error(f"Erreur de traitement : {e}")
    finally:
        client_socket.close()
        for relay_socket in relay_sockets:
            relay_socket.close()

def connect_to_relay(address, port):
    try:
        # Création d'un socket pour la connexion au serveur
        relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        relay_socket.connect((address, port))
        logging.info(f"Connexion au relais {address}:{port} réussie")
        return relay_socket
    except Exception as e:
        logging.error(f"Erreur de connexion au relais {address}:{port} : {e}")
        return None
def start_socks5_proxy():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("localhost", 9000))
    server_socket.listen(5)
    logging.info("Serveur SOCKS5 en écoute sur le port 9000...")

    server_final_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_final_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_final_socket.bind(("10.0.0.2", 80))
    server_final_socket.listen(5)

    while True:
        client_socket, addr = server_socket.accept()
        logging.info(f"Connexion acceptée de {addr}")
        handle_client(client_socket)
    