from django.core.management.base import BaseCommand
from websockets import connect
import asyncio
import json


class Command(BaseCommand):
    def handle(self, *args, **options):
        asyncio.run(Command.main())

    @staticmethod
    async def main():
        server_address = "ws://localhost:8000/ws/socket-server/"
        async with connect(server_address) as ws:
            m = await ws.recv()
            print(m)
            new_m = {"num": 2, "message": "Hello::::"}
            print(new_m)
            await ws.send(json.dumps(new_m))
            print("next step")
            m = await ws.recv()
            print(m)

