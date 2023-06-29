from channels.generic.websocket import AsyncJsonWebsocketConsumer
import asyncio


class ServerStartPointConsumer(AsyncJsonWebsocketConsumer):
    message_queue = asyncio.Queue()

    async def connect(self):
        await self.accept()
        message = {"num": 1, "message": "Hello!"}
        await self.message_queue.put(message)
        await self.send_json(message)

    async def receive_json(self, content, **kwargs):
        old_content = content.copy()
        if content["num"] == 2:
            first_message = await self.message_queue.get()
            content["num"] = 3
            content["message"] = content["message"] + " " + first_message["message"]
            await self.send_json(content)
            print(first_message)
            print(old_content)
            print(content)


class ClientStartPointConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        await self.accept()
