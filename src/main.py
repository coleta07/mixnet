import argparse
import sys

# Importation des fonctions ou des modules pour les rôles relay et client
# Par exemple:
# from relay import relay
from client import start_local_socks5_proxy  # Remplace par le chemin de ton module client si nécessaire
from relay import main_relay
from server import start_final_server

def main():
    # Création du parser d'arguments
    parser = argparse.ArgumentParser(description="Mixnet Test")
    parser.add_argument("-s", "--node_role", help="Role du noeud (relay ou client)", required=True)
    parser.add_argument("-a", "--address", help="Adresse du noeud", required=False)
    parser.add_argument("-l", "--layer", help="Couche du relay", required=False)
    parser.add_argument("-ad", "--address_dest", help="addresse de destination", required=False)
    parser.add_argument("-sa", "--server_address", help="addresse du serveur", required=False)
    

    # Analyse des arguments
    args = parser.parse_args()

    # Vérification et exécution en fonction du rôle du noeud
    if args.node_role == "relay":
        # Appeler ici la fonction relay avec l'adresse (décommenter quand la fonction est définie)
        main_relay(args.address, args.layer)
        print("Fonction relay non implémentée actuellement")
    elif args.node_role == "client":
        # Appeler la fonction client_proxy (pour un client SOCKS5 par exemple)
        start_local_socks5_proxy(args.address, args.address_dest)
    elif args.node_role == "server":
        # Appeler la fonction start_server pour démarrer le serveur
        start_final_server(args.address, args.server_address, args.address_dest)
    else:
        print("Rôle du noeud invalide. Utilisez 'relay' ou 'client'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
