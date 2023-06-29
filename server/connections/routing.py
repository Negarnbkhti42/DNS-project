from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/socket-server/', consumers.ServerStartPointConsumer.as_asgi()),
    re_path(r'ws/socket-client/', consumers.ClientStartPointConsumer.as_asgi()),
]
