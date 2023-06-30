from channels.generic.websocket import AsyncJsonWebsocketConsumer
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import websockets
from websockets.sync.client import connect
import json
import os
from connections.models import *


class Utils:
    @staticmethod
    def load_server_private_key():
        # Load the private key
        with open("server_private_key.pem", "rb") as private_key_file:
            return serialization.load_pem_private_key(
                private_key_file.read(), password=b"mypassword"
            )

    @staticmethod
    def generate_rsa_key_pair():
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return {"private_key": Utils._serialize_private_key(private_key),
                "public_key": Utils._serialize_public_key(private_key.public_key())}

    @staticmethod
    def _serialize_public_key(public_key):
        return Utils._byte_to_string(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    @staticmethod
    def _serialize_private_key(private_key):
        # no encryption
        return Utils._byte_to_string(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    @staticmethod
    def _load_private_key(serialized_private_key):
        return serialization.load_pem_private_key(
            Utils._string_to_byte(serialized_private_key),
            password=None,
        )

    @staticmethod
    def _load_public_key(serialized_public_key):
        return serialization.load_pem_public_key(Utils._string_to_byte(serialized_public_key))

    @staticmethod
    def generate_symmetric_key():
        key = Fernet.generate_key()
        return Utils._byte_to_string(key)

    @staticmethod
    def encrypt_message_with_public_key(message, public_key):
        encrypted_message = Utils._load_public_key(public_key).encrypt(
            Utils._string_to_byte(message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return Utils._byte_to_string(encrypted_message)

    @staticmethod
    def decrypt_message_with_private_key(encrypted_message, private_key):
        decrypted_message = Utils._load_private_key(private_key).decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return Utils._byte_to_string(decrypted_message)

    @staticmethod
    def sign_message_with_private_key(message, private_key):
        signature = Utils._load_private_key(private_key).sign(
            Utils._string_to_byte(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return Utils._byte_to_string(signature)

    @staticmethod
    def verify_signature_with_public_key(signature, message, public_key):
        try:
            public_key.verify(
                signature,
                Utils._string_to_byte(message),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except:
            return False

    @staticmethod
    def encrypt_message_with_symmetric_key(message, symmetric_key):
        cipher_suite = Fernet(Utils._string_to_byte(symmetric_key))
        encrypted_message = cipher_suite.encrypt(Utils._string_to_byte(message))
        return Utils._byte_to_string(encrypted_message)

    @staticmethod
    def decrypt_message_with_symmetric_key(encrypted_message, symmetric_key):
        cipher_suite = Fernet(Utils._string_to_byte(symmetric_key))
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        return Utils._byte_to_string(decrypted_message)

    @staticmethod
    def hash_string(message):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(Utils._string_to_byte(message))
        return Utils._byte_to_string(digest.finalize())

    @staticmethod
    def generate_nonce():
        return Utils._byte_to_string(os.urandom(16))

    @staticmethod
    def _byte_to_string(byte):
        return byte.decode("utf-8")

    @staticmethod
    def _string_to_byte(string):
        return string.encode("utf-8")

    @staticmethod
    def sign_json_message_with_private_key(message, private_key):
        signature = Utils.sign_message_with_private_key(
            "".join([value for key, value in sorted(message.items(), key=lambda t: t[0])]),
            private_key,
        )
        message = message | {"signature": signature}
        return message

    @staticmethod
    def verify_signature_on_json_message(message, public_key):
        public_key_object = Utils._load_public_key(public_key)
        try:
            signature = message.pop("signature")
            return Utils.verify_signature_with_public_key(
                signature,
                Utils.hash_string(
                    "".join([value for key, value in sorted(message.items(), key=lambda t: t[0])])
                ),
                public_key_object,
            )
        except:
            return False


class ServerStartPointConsumer(AsyncJsonWebsocketConsumer):
    queue = asyncio.Queue()

    async def connect(self):
        await self.accept()
        # await self.send("Hello world!")
        # message = await self.receive()
        # print(message)
        # await self.send("ho ho ho!")

        async def receive_json(self, content, **kwargs):
            pass


class ClientStartPointConsumer(AsyncJsonWebsocketConsumer):
    queue = asyncio.Queue()

    async def connect(self):
        await self.accept()

    async def receive_json(self, content, **kwargs):
        if self.queue.empty():
            pass
        else:
            pass



    class SignUp:
        def __init__(self):
            username = None

        async def first_handler(self):
            pass





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
