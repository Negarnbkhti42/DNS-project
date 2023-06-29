import json
from channels.generic.websocket import AsyncWebsocketConsumer


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
