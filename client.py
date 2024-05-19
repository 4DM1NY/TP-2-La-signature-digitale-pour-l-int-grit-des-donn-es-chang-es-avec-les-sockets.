import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def sign_data(data, private_key):
    try:
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        print("Erreur lors de la signature des données :", e)
        return None


def load_private_key():
    try:
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
        return private_key
    except Exception as e:
        print("Erreur lors du chargement de la clé privée :", e)
        return None


def main():
    private_key = load_private_key()
    if private_key is None:
        print("Échec du chargement de la clé privée. Arrêt.")
        return

    message = b"Bonjour, serveur!"
    signature = sign_data(message, private_key)
    if signature is None:
        print("Échec de la signature du message. Arrêt.")
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(("localhost", 9900))
            client_socket.sendall(signature + message)
            print("Message et signature envoyés.")
    except Exception as e:
        print("Erreur lors de la communication par socket :", e)


if __name__ == "__main__":
    main()
