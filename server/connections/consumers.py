import base64
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
from django.db.models import Q


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

    @staticmethod
    @database_sync_to_async
    def get_user_public_key(username):
        return User.objects.get(username=username).public_key

    @staticmethod
    @database_sync_to_async
    def get_user_by_username(username):
        return User.objects.get(username=username)


class ServerData:
    def __init__(self, public_key):
        self.public_key = public_key
        self.nonce = Utils.generate_nonce()

    async def first_handler(self, json_data):
        server_private_key = Utils.load_server_private_key()
        data = json.dumps(json_data)

        m = {
            "data": data,
            "nonce": self.nonce,
        }
        return Utils.sign_json_message_with_private_key(m, server_private_key)

    async def second_handler(self, json_response):
        server_private_key = Utils.load_server_private_key()
        if "nonce" not in json_response or "nonce2" not in json_response or "signature" not in json_response:
            return {
                "status": "error",
            }

        verified = Utils.verify_signature_on_json_message(json_response, self.public_key)
        if not verified:
            return {
                "status": "error",
            }

        if json_response["nonce"] != self.nonce:
            return {
                "status": "error",
            }

        return Utils.sign_json_message_with_private_key({
            "nonce2": json_response["nonce2"],
            "status": "success"
        }, server_private_key)


class ServerStartPointConsumer(AsyncJsonWebsocketConsumer):
    queue = asyncio.Queue()
    username = None

    async def connect(self):
        await self.accept()

    async def receive_json(self, content, **kwargs):
        if self.username is None:
            if "operation" in content:
                while not self.queue.empty():
                    await self.queue.get()

                if content["operation"] == "RA":
                    client_request = ClientRequest(is_go_online=True)
                    result = await client_request.first_handler(content)
                    if result["status"] == "success":
                        await self.queue.put(client_request)
                        await self.send_json(result)
            elif not self.queue.empty():
                obj = await self.queue.get()
                if isinstance(obj, ClientRequest):
                    result = await obj.second_handler(content)
                    if result["status"] == "success":
                        self.username = obj.username
                        await self.send_json(result)
        if self.username is not None:
            if not self.queue.empty():
                server_data = await self.queue.get()
                if isinstance(server_data, ServerData):
                    result = await server_data.second_handler(content)
                    if result["status"] == "success":
                        await self.send_json(result)

            await asyncio.sleep(3)
            server_data = ServerData(await Utils.get_user_public_key(self.username))
            pending_data = await self.get_all_pending_data()
            result = await server_data.first_handler(pending_data)
            await self.queue.put(server_data)
            await self.send_json(result)

    @sync_to_async(thread_sensitive=True)
    def get_all_pending_data(self):
        pending_message = PendingMessage.objects.filter(
            receiver__username=self.username,
            group__isnull=True
        )
        pending_group_message = PendingMessage.objects.filter(
            receiver__username=self.username,
        ).exclude(group__isnull=True)
        new_session = NewSession.objects.filter(
            receiver__username=self.username
        )
        new_group_session = NewGroupSession.objects.filter(
            receiver__username=self.username
        )
        pending_data = dict()
        if pending_message:
            pending_data["pending_message"] = [
                {
                    "sender_username": pending_message.sender.username,
                    "encrypted_message": pending_message.encrypted_message,
                    "public_key": pending_message.sender.public_key,
                    "diffie_hellman_public_parameters_text": pending_message.diffie_hellman_public_parameters_text,
                    "diffie_hellman_public_key_text": pending_message.diffie_hellman_public_key_text,
                }
                for pending_message in pending_message
            ]
        if pending_group_message:
            pending_data["pending_group_message"] = [
                {
                    "sender": pending_group_message.sender.username,
                    "encrypted_message": pending_group_message.encrypted_message,
                    "group": pending_group_message.group.name
                }
                for pending_group_message in pending_group_message
            ]
        if new_session:
            pending_data["new_session"] = [
                {
                    "sender_username": new_session.sender.username,
                    "diffie_hellman_public_parameters_text": new_session.diffie_hellman_public_parameters_text,
                    "sender_diffie_hellman_public_key_text": new_session.sender_diffie_hellman_public_key_text,
                    "receiver_diffie_hellman_public_key_text": new_session.receiver_diffie_hellman_public_key_text,
                }
                for new_session in new_session
            ]
        if new_group_session:
            pending_data["new_group_session"] = [
                {
                    "sender": new_group_session.sender.username,
                    "diffie_hellman_public_parameters_text": new_group_session.diffie_hellman_public_parameters_text,
                    "sender_diffie_hellman_public_key_text": new_group_session.sender_diffie_hellman_public_key_text,
                    "receiver_diffie_hellman_public_key_text":
                        new_group_session.receiver_diffie_hellman_public_key_text,
                    "encrypted_session_key": new_group_session.encrypted_session_key,
                    "group": new_group_session.group.name
                }
                for new_group_session in new_group_session
            ]
        pending_data["users"] = [
            {
                "username": user.username,
                "public_key": user.public_key,
                "online": user.online,
                "diffie_hellman_public_parameters_text": user.diffie_hellman_public_parameters_text,
                "diffie_hellman_public_key_text": user.diffie_hellman_public_key_text,
            }
            for user in User.objects.exclude(username=self.username)
            .filter(public_key__isnull=False)
            .filter(diffie_hellman_public_parameters_text__isnull=False)
            .filter(diffie_hellman_public_key_text__isnull=False)
        ]
        pending_data["groups"] = [
            {
                "name": group.name,
                "group_admin": group.group_admin.username,
                "group_members": [
                    group_member.username
                    for group_member in group.group_members.all()
                ],
            }
            for group in Group.objects.filter(
                Q(group_admin__username=self.username) | Q(group_members__username=self.username)
            )
        ]
        return pending_data

    async def disconnect(self, code):
        if self.username is not None:
            user = await Utils.get_user_by_username(self.username)

            @sync_to_async(thread_sensitive=True)
            def go_offline():
                user.online = False
                user.save()

            await go_offline()


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
            return {
                "status": "error",
            }

        password_and_nonce = json.loads(Utils.decrypt_message_with_private_key(
            message["encrypted_password_and_nonce"], server_private_key
        ))
        password = password_and_nonce["password"]
        nonce = password_and_nonce["nonce"]

        @database_sync_to_async
        def get_user():
            user = None
            try:
                user = User.objects.get(username=message["username"])
            except User.DoesNotExist:
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
            user.go_online = False
            user.public_key = self.public_key
            user.save()

        await login_user()


class ClientRequest:
    def __init__(self, is_go_online=False):
        self.is_go_online = is_go_online
        self.nonce2 = None
        self.public_key = None
        self.username = None
        self.json_request = None

    async def first_handler(self, message):
        server_private_key = Utils.load_server_private_key()
        if "username" not in message \
                or "request" not in message \
                or "nonce" not in message \
                or "signature" not in message:
            return {
                "status": "error",
            }

        self.username = message["username"]
        self.public_key = await Utils.get_user_public_key(self.username)
        self.json_request = json.loads(message["request"])

        if self.is_go_online and self.json_request["operation"] != "GO_ONLINE":
            return {
                "status": "error",
            }

        verified = Utils.verify_signature_on_json_message(
            message, self.public_key
        )

        if not verified:
            return {
                "status": "error",
            }

        self.nonce2 = Utils.generate_nonce()
        return Utils.sign_json_message_with_private_key(
            {
                "status": "success",
                "nonce": message["nonce"],
                "nonce2": self.nonce2,
            },
            server_private_key,
        )

    async def second_handler(self, message):
        if "nonce2" not in message \
                or "signature" not in message:
            return {
                "status": "error",
            }

        server_private_key = Utils.load_server_private_key()

        verified = Utils.verify_signature_on_json_message(
            message, self.public_key
        )

        if not verified or message["nonce2"] != self.nonce2:
            return {
                "status": "error",
            }

        answer = json.dumps(await self.get_json_answer())
        return Utils.sign_json_message_with_private_key(
            {
                "status": "success",
                "nonce2": self.nonce2,
                "answer": Utils.encrypt_message_with_public_key(
                    answer, self.public_key
                ),
            },
            server_private_key,
        )

    async def get_json_answer(self):
        if self.json_request["operation"] == "GO_ONLINE":
            return await self.go_online()
        elif self.json_request["operation"] == "LOGOUT":
            return await self.logout()
        elif self.json_request["operation"] == "GET_DIFFIE_HELLMAN":
            return await self.get_diffie_hellman()
        elif self.json_request["operation"] == "CREATE_GROUP":
            return await self.create_group()
        elif self.json_request["operation"] == "UPDATE_GROUP":
            return await self.update_group()
        elif self.json_request["operation"] == "SEND_MESSAGE":
            return await self.send_message()
        elif self.json_request["operation"] == "SEND_GROUP_MESSAGE":
            return await self.send_group_message()
        elif self.json_request["operation"] == "NEW_SESSION":
            return await self.new_session()
        else:
            return {
                "status": "error",
            }

    async def go_online(self):
        pass

    async def logout(self):
        user = await Utils.get_user_by_username(self.username)

        @sync_to_async(thread_sensitive=True)
        def logout_user():
            user.logged_in = False
            user.online = False
            user.public_key = None
            user.diffie_hellman_public_parameters_text = None
            user.diffie_hellman_public_key_text = None
            user.save()

        await logout_user()

        return {"status": "success"}

    async def get_diffie_hellman(self):
        pass

    async def create_group(self):
        pass

    async def update_group(self):
        pass

    async def send_message(self):
        pass

    async def send_group_message(self):
        pass

    async def new_session(self):
        pass


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
                elif result["status"] == "failed":
                    await self.send_json(result)
            elif content["operation"] == "RA":
                client_request = ClientRequest()
                result = await client_request.first_handler(content)
                if result["status"] == "success":
                    await self.queue.put(client_request)
                    await self.send_json(result)
        elif not self.queue.empty():
            obj = await self.queue.get()
            if isinstance(obj, Login):
                await obj.second_handler(content)
            elif isinstance(obj, ClientRequest):
                result = await obj.second_handler(content)
                if result["status"] == "success":
                    await self.send_json(result)

    async def sign_up(self, message):

        server_private_key = Utils.load_server_private_key()

        verified = Utils.verify_signature_on_json_message(
            message, message["public_key"]
        )

        if not verified:
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
