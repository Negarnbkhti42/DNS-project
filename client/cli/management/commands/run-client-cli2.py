from django.core.management.base import BaseCommand
import json
import asyncio
import websockets


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
    async def signup(queue: asyncio.Queue):
        username = input("Enter username: ")
        password = input("Enter password: ")
        await queue.put(
            json.dumps(
                {
                    "operation": "SU",
                    "username": username,
                    "password": password,
                }
            )
        )
        await queue2.get()

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
            self.interact_with_user()
        )

    async def server_start_point(self):
        server_address = self.server_address + "socket-server/"
        async with websockets.connect(server_address) as ws:
            while not self.terminate_event.is_set():
                server_message = await ws.recv()
                print("Received from server:", server_message)

                # Check if the server message indicates the start of a conversation
                if server_message == "Start conversation":
                    # Add an action to the queue to indicate the start of the conversation
                    await self.action_queue.put("start_conversation")

    async def client_start_point(self):
        server_address = self.server_address + "socket-client/"
        async with websockets.connect(server_address) as ws:
            while not self.terminate_event.is_set():
                # Wait for an action in the queue
                action = await self.action_queue.get()

                if action == "start_conversation":
                    # Start a conversation with the server
                    await ws.send("Hello, server! Let's start the conversation.")
                    response = await ws.recv()
                    print("Received from server:", response)

    async def interact_with_user(self):
        while not self.terminate_event.is_set():
            user_input = input("Enter an action: ")
            # Store the action in the queue
            await self.action_queue.put(user_input)

