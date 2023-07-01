import base64
import traceback
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import json
import os
from connections.models import *
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async


class Utils:
    @staticmethod
    def load_server_private_key():
        # Load the private key
        with open("server_private_key.pem", "rb") as private_key_file:
            return Utils._serialize_private_key(serialization.load_pem_private_key(
                private_key_file.read(), password=b"mypassword"
            ))

    @staticmethod
    def generate_rsa_key_pair():
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return {
            "private_key": Utils._serialize_private_key(private_key),
            "public_key": Utils._serialize_public_key(private_key.public_key()),
        }

    @staticmethod
    def _serialize_public_key(public_key):
        return Utils._byte_to_string(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    @staticmethod
    def _serialize_private_key(private_key):
        # no encryption
        return Utils._byte_to_string(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    @staticmethod
    def _load_private_key(serialized_private_key):
        return serialization.load_pem_private_key(
            Utils._string_to_byte(serialized_private_key),
            password=None,
        )

    @staticmethod
    def _load_public_key(serialized_public_key):
        return serialization.load_pem_public_key(
            Utils._string_to_byte(serialized_public_key)
        )

    @staticmethod
    def generate_symmetric_key():
        key = Fernet.generate_key()
        return Utils._byte_to_string(key)

    @staticmethod
    def encrypt_message_with_public_key(message, public_key):
        encrypted_message = base64.b64encode(Utils._load_public_key(public_key).encrypt(
            Utils._string_to_byte(message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ))
        return Utils._byte_to_string(encrypted_message)

    @staticmethod
    def decrypt_message_with_private_key(encrypted_message, private_key):
        decrypted_message = Utils._load_private_key(private_key).decrypt(
            base64.b64decode(Utils._string_to_byte(encrypted_message)),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return Utils._byte_to_string(decrypted_message)

    @staticmethod
    def sign_message_with_private_key(message, private_key):
        signature = base64.b64encode(Utils._load_private_key(private_key).sign(
            Utils._string_to_byte(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        ))
        return Utils._byte_to_string(signature)

    @staticmethod
    def verify_signature_with_public_key(signature, message, public_key):
        try:
            public_key.verify(
                base64.b64decode(Utils._string_to_byte(signature)),
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
        return os.urandom(16).hex()

    @staticmethod
    def _byte_to_string(byte):
        return byte.decode("utf-8")

    @staticmethod
    def _string_to_byte(string):
        return string.encode("utf-8")

    @staticmethod
    def sign_json_message_with_private_key(message, private_key):
        signature = Utils.sign_message_with_private_key(
            "".join(
                [value for key, value in sorted(message.items(), key=lambda t: t[0])]
            ),
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
                "".join(
                    [
                        value
                        for key, value in sorted(
                        message.items(), key=lambda t: t[0])
                    ]
                ),
                public_key_object,
            )
        except:
            return False


class ServerStartPointConsumer(AsyncJsonWebsocketConsumer):
    queue = asyncio.Queue()

    async def connect(self):
        await self.accept()

        async def receive_json(self, content, **kwargs):
            pass


class Login:
    def __init__(self):
        self.nonce2 = None
        self.password = None
        self.public_key = None
        self.username = None

    async def first_handler(self, message):
        server_private_key = Utils.load_server_private_key()

        verified = Utils.verify_signature_on_json_message(
            message, message["public_key"]
        )
        if not verified:
            return Utils.sign_json_message_with_private_key(
                {
                    "status": "error",
                },
                server_private_key,
            )

        password_and_nonce = json.loads(Utils.decrypt_message_with_private_key(
            message["encrypted_password_and_nonce"], server_private_key
        ))
        password = password_and_nonce["password"]
        nonce = password_and_nonce["nonce"]

        @database_sync_to_async
        def get_user():
            user = User.objects.get(username=message["username"])
            if user is None:
                return None

            if user.password == password:
                return user
            return None

        user = await get_user()
        if user is None:
            return Utils.sign_json_message_with_private_key(
                {
                    "nonce": nonce,
                    "status": "failed",
                },
                server_private_key,
            )

        nonce2 = Utils.generate_nonce()

        response = Utils.sign_json_message_with_private_key(
            {
                "nonce": nonce,
                "nonce2": nonce2,
                "status": "success",
            },
            server_private_key,
        )

        self.nonce2 = nonce2
        self.password = password
        self.public_key = message["public_key"]
        self.username = message["username"]

        return response

    async def second_handler(self, message):
        server_private_key = Utils.load_server_private_key()

        verified = Utils.verify_signature_on_json_message(
            message, self.public_key
        )
        if not verified:
            return

        password_and_nonce = json.loads(Utils.decrypt_message_with_private_key(
            message["encrypted_password_and_nonce"], server_private_key
        ))

        if password_and_nonce["nonce2"] != self.nonce2 \
                or password_and_nonce["password"] != self.password:
            return

        @sync_to_async(thread_sensitive=True)
        def login_user():
            user = User.objects.get(username=self.username)
            user.logged_in = True
            user.online = True
            user.save()

        await login_user()


class ClientStartPointConsumer(AsyncJsonWebsocketConsumer):
    queue = asyncio.Queue()

    async def connect(self):
        await self.accept()

    async def receive_json(self, content, **kwargs):
        if "operation" in content:
            while not self.queue.empty():
                await self.queue.get()

            if content["operation"] == "SU":
                await self.sign_up(content)
            elif content["operation"] == "NK":
                login = Login()
                result = await login.first_handler(content)
                if result["status"] == "success":
                    await self.queue.put(login)
                await self.send_json(result)
        elif not self.queue.empty():
            obj = await self.queue.get()
            if isinstance(obj, Login):
                await obj.second_handler(content)

    async def sign_up(self, message):

        server_private_key = Utils.load_server_private_key()

        verified = Utils.verify_signature_on_json_message(
            message, message["public_key"]
        )

        if not verified:
            await self.send_json(Utils.sign_json_message_with_private_key(
                {"status": "error"}, server_private_key
            ))
            return

        @database_sync_to_async
        def user_exists():
            return User.objects.filter(username=message["username"]).exists()

        if await user_exists():
            await self.send_json(Utils.sign_json_message_with_private_key(
                {"status": "failed"}, server_private_key
            ))
            return

        @sync_to_async(thread_sensitive=True)
        def add_user():
            user = User.objects.create(
                username=message["username"],
                password=Utils.decrypt_message_with_private_key(
                    message["encrypted_password"], server_private_key
                ),
                public_key=message["public_key"],
                online=True,
                logged_in=True,
            )
            user.save()

        await add_user()

        await self.send_json(Utils.sign_json_message_with_private_key(
            {
                "status": "success",
                "username": message["username"],
            },
            server_private_key
        ))
