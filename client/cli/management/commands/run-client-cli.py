from django.core.management.base import BaseCommand
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import asyncio
import websockets
import json


class Command(BaseCommand):
    help = "Closes the specified poll for voting"

    def handle(self, *args, **options):
        pass


# sign up using websockets and asyncio
async def signup():
    uri = "http://localhost:8000/"  # Replace with your server's websocket URL
    async with websockets.connect(uri) as websocket:
        username = input("Enter username: ")
        password = input("Enter password: ")
        public_key = 0  # generate public key
        # encrypt password with server public key
        encrypted_pass = 0

        # hash and sign whole data with client private key
        signature = ""

        # Send the sign-up request
        await websocket.send(
            json.dumps(
                {
                    "operation": "SU",
                    "username": username,
                    "public_key": public_key,
                    "encrypted_password": encrypted_pass,
                    "signature": signature,
                }
            )
        )

        # Wait for the response
        response = await websocket.recv()
        print(f"Response: {response}")


async def login():
    uri = "http://localhost:8000/"  # Replace with your server's websocket URL
    async with websockets.connect(uri) as websocket:
        username = input("Enter username: ")
        password = input("Enter password: ")
        public_key = 0  # generate public key
        # encrypt password with server public key
        nonce = 0  # generate nonce
        encrypted_pass_and_nonce = 0

        # hash and sign whole data with client private key
        signature = ""

        # Send the login request
        await websocket.send(
            json.dumps(
                {
                    "operation": "NK",
                    "username": username,
                    "public_key": public_key,
                    "encrypted_password_and_nonce": encrypted_pass_and_nonce,
                    "signature": signature,
                }
            )
        )

        # Wait for the response
        response = await websocket.recv()
        print(f"Response: {response}")
