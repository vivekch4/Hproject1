# asgi.py
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_checksheet1.settings')

# Initialize Django ASGI application early to configure settings
django_asgi_app = get_asgi_application()

# Import checksheet1.routing *after* Django settings are initialized
import checksheet1.routing

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(checksheet1.routing.websocket_urlpatterns)
    ),
})