from django.core.management.base import BaseCommand
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import websockets
import json
import os


class Command(BaseCommand):
    help
    "Closes the specified poll for voting"

    def handle(self, *args, **options):
        pass


# sign up using websockets and asyncio
async def signup(server_public_key):
    uri = "http://localhost:8000/"  # Replace with your server's websocket URL
    async with websockets.connect(uri) as websocket:
        message = {}
        message["operation"] = "SU"
        message["username"] = input("Enter username: ")

        password = input("Enter password: ")

        public_key = load_public_key()
        message["public_key"] = public_key

        message["encrypted_password"] = encrypt_message_with_public_key(
            password, server_public_key
        )

        signature = sign_message_with_private_key(
            hash_string(json.dumps(message)), load_private_key()
        )

        # Send the sign-up request
        message["signature"] = signature
        await websocket.send(json.dumps(message))

        # Wait for the response
        response = await websocket.recv()
        response_dict = json.loads(response)
        verify = verify_signature_with_public_key(
            response_dict["signature"], response_dict["message"], server_public_key
        )

        return verify


async def login(server_public_key):
    uri = "http://localhost:8000/"  # Replace with your server's websocket URL
    async with websockets.connect(uri) as websocket:
        message = {}
        message["operation"] = "NK"
        message["username"] = input("Enter username: ")

        password = input("Enter password: ")

        public_key = load_public_key()
        message["public_key"] = public_key

        nonce = generate_nonce()  # generate nonce
        message["encrypted_password_and_nonce"] = encrypt_message_with_public_key(
            json.dumps({"password": password, "nonce": nonce}), server_public_key
        )

        # hash and sign whole data with client private key
        signature = sign_message_with_private_key(
            hash_string(message),
            load_private_key(),
        )

        message["signature"] = signature

        # Send the login request
        await websocket.send(json.dumps(message))

        # Wait for the response
        response = await websocket.recv()
        response_dict = json.loads(response)

        if nonce != response_dict["nonce"]:
            print("Nonce is not equal")
            return False

        verify = verify_signature_with_public_key(
            response_dict["signature"],
            json.dumps(
                {"nonce": response_dict["nonce"], "nonce2": response_dict["nonce2"]}
            ),
            server_public_key,
        )

        if not verify:
            return False

        message = {}

        message["encrypted_password_nonce"] = encrypt_message_with_public_key(
            json.dumps({"password": password, "nonce2": response_dict["nonce2"]}),
            server_public_key,
        )

        signature = sign_message_with_private_key(
            hash_string(message), load_private_key()
        )
        message["signature"] = signature

        await websocket.send(json.dumps(message))

        print(f"Response: {response}")


def generate_key_pair():
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save the private key
    with open("server_private_key.pem", "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    b"mypassword"
                ),
            )
        )

    # Get the corresponding public key
    public_key = private_key.public_key()

    # Save the public key
    with open("server_public_key.pem", "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def load_private_key():
    # Load the private key
    with open("server_private_key.pem", "rb") as private_key_file:
        return serialization.load_pem_private_key(
            private_key_file.read(), password=b"mypassword"
        )


def load_public_key():
    # Load the public key
    with open("server_public_key.pem", "rb") as public_key_file:
        return serialization.load_pem_public_key(public_key_file.read())


def generate_key():
    # Generate a new encryption key
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    # Load the encryption key
    with open("key.key", "rb") as key_file:
        return key_file.read()


def encrypt_message_with_public_key(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_message


def decrypt_message_with_private_key(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_message.decode()


def sign_message_with_private_key(message, private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature_with_public_key(signature, message, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False


def encrypt_message_with_symmetric_key(message, symmetric_key):
    cipher_suite = Fernet(symmetric_key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message


def decrypt_message_with_symmetric_key(encrypted_message, symmetric_key):
    cipher_suite = Fernet(symmetric_key)
    decrypted_message = cipher_suite.decrypt(encrypted_message)
    return decrypted_message.decode()


def hash_string(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()


def generate_nonce():
    return os.urandom(16)


def send_data(data, socket):
    nonce = generate_nonce()
    m = data + nonce
    hashed_data = hash_string(m)
    signature = sign_message_with_private_key(hashed_data, load_private_key())
    socket.sendall(m.encode())
    socket.sendall(signature.encode())


def receive_data(socket):
    data = socket.recv(1024)
    signature = socket.recv(1024)
    hashed_data = hash_string(data)
    if verify_signature_with_public_key(signature, hashed_data, load_public_key()):
        return data
    else:
        return None
