from django.core.management.base import BaseCommand
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import websockets
from websockets.sync.client import connect
import json
import os


class _CLI:
    @staticmethod
    async def main_page():
        options = ["Sign up", "Login", "Exit"]
        choices = [str(i + 1) for i in range(len(options))]
        while True:
            print("Welcome to the chat app!")
            print("Please select an option:")
            for i in range(len(options)):
                print(f"{i + 1}. {options[i]}")
            choice = input("Enter your choice: ").replace(" ", "")
            # check if choice is number and in range of options and the return the choice
            if choice in choices:
                return options[int(choice) - 1]

    @staticmethod
    async def signup():
        Username = input("Enter username:")
        password = input("enter password:")

    @staticmethod
    async def login():
        username = input("Enter username: ")
        password = input("Enter password: ")


class Command(BaseCommand):
    help = "Closes the specified poll for voting"

    server_address = "ws://localhost:8000/ws/"
    action_queue = asyncio.Queue()
    terminate_event = asyncio.Event()

    def handle(self, *args, **options):
        try:
            asyncio.run(self.main())
        except KeyboardInterrupt:
            self.terminate_event.set()

    async def main(self):
        await asyncio.gather(
            self.server_start_point(),
            self.client_start_point(),
            self.interact_with_user(),
        )

    async def server_start_point(self):
        server_address = self.server_address + "socket-server/"
        with connect(server_address) as ws:
            while not self.terminate_event.is_set():
                server_message = ws.recv()
                print("Received from server:", server_message)

                # Check if the server message indicates the start of a conversation
                if server_message == "Start conversation":
                    # Add an action to the queue to indicate the start of the conversation
                    self.action_queue.put("start_conversation")

    async def client_start_point(self):
        server_address = self.server_address + "socket-client/"
        with connect(server_address) as ws:
            while not self.terminate_event.is_set():
                # Wait for an action in the queue
                action = self.action_queue.get()

                if action == "start_conversation":
                    # Start a conversation with the server
                    ws.send("Hello, server! Let's start the conversation.")
                    response = ws.recv()
                    print("Received from server:", response)

    async def interact_with_user(self):
        while not self.terminate_event.is_set():
            user_input = input("Enter an action: ")
            # Store the action in the queue
            await self.action_queue.put(user_input)

    async def signup(
        self,
        username: str,
        password: str,
        server_public_key: rsa.RSAPublicKeyWithSerialization,
        websocket,
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
        server_public_key: rsa.RSAPublicKeyWithSerialization,
        websocket,
    ):
        message = {}
        message["operation"] = "NK"
        message["username"] = username

        public_key = self.load_public_key(asByte=True)
        message["public_key"] = public_key

        nonce = self.generate_nonce()  # generate nonce
        message["encrypted_password_and_nonce"] = self.encrypt_message_with_public_key(
            json.dumps({"password": password, "nonce": nonce}), server_public_key
        )

        # hash and sign whole data with client private key
        signature = self.sign_message_with_private_key(
            self.hash_string(
                "NK" + username + public_key + message["encrypted_password_and_nonce"]
            ),
            self.load_private_key(),
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

        verify = self.verify_signature_with_public_key(
            response_dict["signature"],
            json.dumps(
                {"nonce": response_dict["nonce"], "nonce2": response_dict["nonce2"]}
            ),
            server_public_key,
        )

        if not verify:
            return False

        message = {}

        message["encrypted_password_nonce"] = self.encrypt_message_with_public_key(
            json.dumps({"password": password, "nonce2": response_dict["nonce2"]}),
            server_public_key,
        )

        signature = self.sign_message_with_private_key(
            self.hash_string(password + response_dict["nonce2"]),
            self.load_private_key(),
        )
        message["signature"] = signature

        await websocket.send(json.dumps(message))

        print(f"Response: {response}")

    async def send_request(self, request: str, server_public_key: str, websocket):
        message = {}
        message["operation"] = request
        message["nonce"] = self.generate_nonce()
        signature = self.sign_message_with_private_key(
            self.hash_string(request + message["nonce"]), self.load_private_key()
        )
        message["signature"] = signature

        websocket.send(json.dumps(message))

        response = websocket.recv()
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

    # utility functions

    def generate_key_pair(self):
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Save the private key
        with open("client_private_key.pem", "wb") as private_key_file:
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
        with open("client_public_key.pem", "wb") as public_key_file:
            public_key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def load_private_key(self, asByte: bool = False):
        # Load the private key
        with open("client_private_key.pem", "rb") as private_key_file:
            if asByte:
                return private_key_file.read()
            return serialization.load_pem_private_key(
                private_key_file.read(), password=b"mypassword"
            )

    def load_public_key(self, asByte: bool = False):
        # Load the public key
        with open("client_public_key.pem", "rb") as public_key_file:
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

    # def send_data(self, data, socket):
    #     nonce = generate_nonce()
    #     m = data + nonce
    #     hashed_data = hash_string(m)
    #     signature = sign_message_with_private_key(hashed_data, load_private_key())
    #     socket.sendall(m.encode())
    #     socket.sendall(signature.encode())

    # def receive_data(self, socket):
    #     data = socket.recv(1024)
    #     signature = socket.recv(1024)
    #     hashed_data = hash_string(data)
    #     if verify_signature_with_public_key(signature, hashed_data, load_public_key()):
    #         return data
    #     else:
    #         return None
