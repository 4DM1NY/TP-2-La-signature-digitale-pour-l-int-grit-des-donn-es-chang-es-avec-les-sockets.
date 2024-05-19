import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    try:
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend()
            )
        return public_key
    except Exception as e:
        print("Erreur de chargement de la public key:", e)
        return None

def verify_signature(signature, data, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print("Echec de verification de la signature:", e)
        return False

def main():
    public_key = load_public_key()
    if public_key is None:
        print("Erreur de chargement de la public key. Exit...")
        return

    # Creation et configuration des socket 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 9900))
        s.listen(1)
        print("Serveur en ecoute...")

        while True:
            try:
                connection, _ = s.accept()
                with connection:
                    print("Connection etablit.")
                    received_data = connection.recv(1024)
                    if len(received_data) < 256:
                        print("Les données reçues sont trop courtes pour contenir une signature valide.")
                        continue

                    message, signature = received_data[256:], received_data[:256]
                    if verify_signature(signature, message, public_key):
                        print("Signature verifier")
                    else:
                        print("signature invalid ")
            except Exception as e:
                print("Erreur lors du traitement de la connexion:", e)

if __name__ == "__main__":
    main()
