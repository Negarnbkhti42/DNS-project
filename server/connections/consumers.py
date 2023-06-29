from channels.generic.websocket import AsyncWebsocketConsumer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import websockets
from websockets.sync.client import connect
import json
import os

from models import User


class ServerStartPointConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.send("Hello world!")
        message = await self.receive()
        print(message)
        await self.send("ho ho ho!")


class ClientStartPointConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def signup(self, message: dict):
        public_key = serialization.load_pem_public_key(message["public_key"])

        if not self.verify_signature_with_public_key(
            message["signature"],
            self.hash_string(
                "SU"
                + message["username"]
                + message["public_key"]
                + message["encrypted_password"]
            ),
            public_key,
        ):
            return False

        user = User.objects.get(username=message["username"])
        if user is not None:
            return "user exists"

        newUser = User(
            username=message["username"],
            password=self.decrypt_message_with_private_key(
                message["encrypted_password"], self.load_private_key
            ),
            logged_in=True,
            online=True,
        )
        return message["username"]

    async def login(self, message):
        public_key = serialization.load_pem_public_key(message["public_key"])

        if not self.verify_signature_with_public_key(
            message["signature"],
            self.hash_string(
                "NK"
                + message["username"]
                + message["public_key"]
                + message["encrypted_password_and_nonce"]
            ),
            public_key,
        ):
            return False

        password_and_nonce = json.loads(
            self.decrypt_message_with_private_key(
                message["encrypted_password_and_nonce"], self.load_private_key()
            )
        )
        password = password_and_nonce["password"]
        nonce = password_and_nonce["nonce"]

        user = User.objects.get(username=message["username"], password=password)
        if user is None:
            return "user doesn't exist"

        nonce2 = self.generate_nonce()
        signature = self.sign_message_with_private_key(
            self.hash_string(nonce + nonce2), self.load_private_key()
        )

        await self.send(
            json.dumps({"nonce": nonce, "nonce2": nonce2, "signature": signature})
        )

        response = await self.receive()
        response = json.loads(response)

        if self.verify_signature_with_public_key(
            response["signature"],
            self.hash_string(response["encrypted_password_nonce"]),
            public_key,
        ):
            password_nonce = json.loads(
                self.decrypt_message_with_private_key(
                    response["encrypted_password_nonce"], self.load_private_key()
                )
            )

            password2 = password_nonce["password"]
            nonce2_repeat = password_nonce["nonce2"]

            if (password == password2) and (nonce2_repeat == nonce2):
                user.logged_in = True
                user.online = True
                user.public_key = message["public_key"]
                user.save()

    # utility functions

    def generate_key_pair(self):
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

    def load_private_key(self, asByte: bool = False):
        # Load the private key
        with open("server_private_key.pem", "rb") as private_key_file:
            if asByte:
                return private_key_file.read()
            return serialization.load_pem_private_key(
                private_key_file.read(), password=b"mypassword"
            )

    def load_public_key(self, asByte: bool = False):
        # Load the public key
        with open("server_public_key.pem", "rb") as public_key_file:
            if asByte:
                return public_key_file.read()
            return serialization.load_pem_public_key(public_key_file.read())

    def generate_key(self):
        # Generate a new encryption key
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)

    def load_key(self):
        # Load the encryption key
        with open("key.key", "rb") as key_file:
            return key_file.read()

    def encrypt_message_with_public_key(self, message, public_key):
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted_message

    def decrypt_message_with_private_key(self, encrypted_message, private_key):
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_message.decode()

    def sign_message_with_private_key(self, message, private_key):
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return signature

    def verify_signature_with_public_key(self, signature, message, public_key):
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

    def encrypt_message_with_symmetric_key(self, message, symmetric_key):
        cipher_suite = Fernet(symmetric_key)
        encrypted_message = cipher_suite.encrypt(message.encode())
        return encrypted_message

    def decrypt_message_with_symmetric_key(self, encrypted_message, symmetric_key):
        cipher_suite = Fernet(symmetric_key)
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        return decrypted_message.decode()

    def hash_string(self, message):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode())
        return digest.finalize()

    def generate_nonce(self):
        return os.urandom(16)
