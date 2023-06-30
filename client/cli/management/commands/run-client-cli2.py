import sys

from cryptography.hazmat.backends import default_backend
from django.core.management.base import BaseCommand
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import websockets
from websockets.sync.client import connect
import json
import os
from cli.models import *
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async


class Utils:
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
    def load_server_public_key():
        with open("server_public_key.pem", "rb") as public_key_file:
            return Utils._byte_to_string(public_key_file.read())

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
    def generate_diffie_hellman_parameters():
        shared_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key = shared_parameters.generate_private_key()
        public_key = private_key.public_key()
        return {"shared_parameters": Utils._serialize_diffie_hellman_shared_parameters(shared_parameters),
                "public_key": Utils._serialize_diffie_hellman_public_key(public_key),
                "private_key": Utils._serialize_diffie_hellman_private_key(private_key)}

    @staticmethod
    def _serialize_diffie_hellman_public_key(public_key):
        return Utils._byte_to_string(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo))

    @staticmethod
    def _load_diffie_hellman_public_key(public_key):
        return serialization.load_pem_public_key(public_key)

    @staticmethod
    def _serialize_diffie_hellman_private_key(private_key):
        return Utils._byte_to_string(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                               format=serialization.PrivateFormat.PKCS8,
                                                               encryption_algorithm=serialization.NoEncryption()))

    @staticmethod
    def _load_diffie_hellman_private_key(serialized_private_key):
        return serialization.load_pem_private_key(Utils._string_to_byte(serialized_private_key), password=None)

    @staticmethod
    def _serialize_diffie_hellman_shared_parameters(shared_parameters):
        return Utils._byte_to_string(shared_parameters.parameter_bytes(encoding=serialization.Encoding.PEM,
                                                                       format=serialization.ParameterFormat.PKCS3))

    @staticmethod
    def _load_diffie_hellman_shared_parameters(serialized_shared_parameters):
        return serialization.load_pem_parameters(Utils._string_to_byte(serialized_shared_parameters))

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


class Command(BaseCommand):
    help = "Closes the specified poll for voting"

    server_address = "ws://localhost:8000/ws/"
    server_start_point_queue = asyncio.Queue()
    terminate_event = asyncio.Event()
    client_ws = None
    server_ws = None
    client_section = "Check Logged In Section"

    def handle(self, *args, **options):
        try:
            asyncio.run(self.main())
        except KeyboardInterrupt:
            self.terminate_event.set()

    async def main(self):
        await asyncio.gather(
            self.server_start_point(),
            self.client_start_point(),
        )

    async def send_json_client_ws(self, json_data):
        await self.client_ws.send(json.dumps(json_data))

    async def receive_json_client_ws(self):
        return json.loads(await self.client_ws.recv())
    async def send_json_server_ws(self, json_data):
        await self.server_ws.send(json.dumps(json_data))

    async def receive_json_server_ws(self):
        return json.loads(await self.server_ws.recv())

    @database_sync_to_async
    def get_my_user(self):
        return User.objects.get(is_me=True)

    @database_sync_to_async
    def get_user_public_key(self, username):
        return User.objects.get(username=username).public_key

    async def server_start_point(self):
        server_address = self.server_address + "socket-server/"
        async with websockets.connect(server_address) as ws:
            self.server_ws = ws
            while not self.terminate_event.is_set():
                break

    async def client_start_point(self):
        server_address = self.server_address + "socket-client/"
        async with websockets.connect(server_address) as ws:
            self.client_ws = ws
            while not self.terminate_event.is_set():
                if self.client_section == "Check Logged In Section":
                    await self.check_logged_in_section()
                elif self.client_section == "Pre Login Page":
                    await self.pre_login_page()
                elif self.client_section == "Login Page":
                    await self.login_page()
                elif self.client_section == "Sign Up Page":
                    await self.sign_up_page()

    @database_sync_to_async
    def check_logged_in_section(self):
        logged_in = User.objects.filter(is_me=True).exists()
        if logged_in:
            self.client_section = "Main Page"
        else:
            self.client_section = "Pre Login Page"

    async def pre_login_page(self):
        choices = ["Login Page", "Sign Up Page"]
        options = [str(i + 1) for i in range(len(choices))]
        while True:
            print("Choose an option:")
            for i in range(len(choices)):
                print("{}. {}".format(i + 1, choices[i]))
            choice = input("Enter your choice: ")
            if choice in options:
                self.client_section = choices[int(choice) - 1]
            else:
                print("Invalid choice. Try again.")

    async def login_page(self):
        try:
            while True:
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                if username and password and " " not in username and " " not in password:
                    result = await self.login(username, password)
                    if result["status"] == "success":
                        self.client_section = "Main Page"
                        break
                    if result["status"] == "failed":
                        print("Wrong Username or Password. Try again.")
                    if result["status"] == "error":
                        print("Server Error. Try again.")
                        # decrease trust level
                else:
                    print("Invalid input. Try again.")
        except KeyboardInterrupt:
            self.client_section = "Pre Login Page"

    async def sign_up_page(self):
        try:
            while True:
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                if username and password and " " not in username and " " not in password:
                    result = await self.signup(username, password)
                    if result["status"] == "success":
                        self.client_section = "Main Page"
                        break
                    if result["status"] == "failed":
                        print("Username already exists. Try again.")
                    if result["status"] == "error":
                        print("Server Error. Try again.")
                        # decrease trust level
                else:
                    print("Invalid input. Try again.")
        except KeyboardInterrupt:
            self.client_section = "Pre Login Page"



    async def signup(
        self,
        username: str,
        password: str,
    ):
        message = {}
        message["operation"] = "SU"
        message["username"] = username

        public_key = str(self.load_public_key(asByte=True))
        message["public_key"] = public_key

        message["encrypted_password"] = self.encrypt_message_with_public_key(
            password, server_public_key
        )

        signature = self.sign_message_with_private_key(
            self.hash_string(
                "SU" + username + public_key + message["encrypted_password"]
            ),
            self.load_private_key(),
        )

        # Send the sign-up request
        message["signature"] = signature
        await websocket.send(json.dumps(message))

        # Wait for the response
        response = await websocket.recv()
        response_dict = json.loads(response)
        verify = self.verify_signature_with_public_key(
            response_dict["signature"], response_dict["message"], server_public_key
        )

        return verify and (response_dict["message"] == username)

    async def login(
        self,
        username,
        password,
    ):
        new_rsa_key_pair = Utils.generate_rsa_key_pair()
        server_public_key = Utils.load_server_public_key()

        nonce = Utils.generate_nonce()
        m = json.dumps({"nonce": nonce, "password": password})
        encrypted_m = Utils.encrypt_message_with_public_key(m, server_public_key)
        m2 = {"operation": "NK",
              "username": username,
              "public_key": new_rsa_key_pair['public_key'],
              "encrypted_password_and_nonce": encrypted_m}
        message = Utils.sign_json_message_with_private_key(m2, new_rsa_key_pair['private_key'])
        await self.send_json_client_ws(message)

        response = await self.receive_json_client_ws()
        verified = Utils.verify_signature_on_json_message(response, server_public_key)
        if not verified:
            return {"status": "error"}
        nonce_2 = response['nonce']
        nonce2_2 = response['nonce2']
        status_2 = response['status']
        if nonce != nonce_2:
            return {"status": "error"}
        if status_2 == "failed":
            return {"status": "failed"}
        if status_2 != "success":
            return {"status": "error"}

        m_3 = json.dumps({
            "password": password,
            "nonce2": nonce2_2,
        })
        m2_3 = {
            "encrypted_password_and_nonce": Utils.encrypt_message_with_public_key(m_3, server_public_key)
        }
        message_3 = Utils.sign_json_message_with_private_key(m2_3, new_rsa_key_pair['private_key'])
        await self.send_json_client_ws(message_3)

        @sync_to_async(thread_sensitive=True)
        def update_user():
            if User.objects.filter(is_me=True).exists():
                user = User.objects.get(is_me=True)
                user.is_me = False
                user.public_key = None
                user.private_key = None
                user.password = None
                user.save()
            user = User.objects.get_or_create(username=username)
            user.password = password
            user.public_key = new_rsa_key_pair['public_key']
            user.private_key = new_rsa_key_pair['private_key']
            user.is_me = True
            user.save()
        await update_user()

        return {"status": "success"}

    async def send_request(self, request: str, server_public_key: str, websocket):
        message = {}
        message["operation"] = request
        message["nonce"] = self.generate_nonce()
        signature = self.sign_message_with_private_key(
            self.hash_string(request + message["nonce"]), self.load_private_key()
        )
        message["signature"] = signature

        await websocket.send(json.dumps(message))

        response = await websocket.recv()
        response_dict = json.loads(response)

        if response_dict["nonce"] != message["nonce"]:
            return None

        verify = self.verify_signature_with_public_key(
            response_dict["signature"],
            response_dict["answer"] + response_dict["nonce"] + response_dict["nonce2"],
            server_public_key,
        )

        if verify:
            return response_dict["answer"]

        return None
