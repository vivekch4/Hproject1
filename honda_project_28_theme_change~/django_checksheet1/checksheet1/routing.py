# yourapp/routing.py

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r"ws/production/$", consumers.ProductionConsumer.as_asgi()),
    re_path(r"ws/form_requests/$", consumers.FormRequestConsumer.as_asgi()),
]
