# checksheet1/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async


class ProductionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print(f"WebSocket connected: {self.channel_name}")
        await self.channel_layer.group_add("production_group", self.channel_name)
        await self.accept()
        await self.send(text_data=json.dumps({"message": "Connected to WebSocket"}))
        print("Sent connection confirmation to client")

    async def disconnect(self, close_code):
        print(f"WebSocket disconnected: {close_code}")
        await self.channel_layer.group_discard("production_group", self.channel_name)

    async def send_production_update(self, event):
        print(f"Received event in consumer: {event}")
        data = event.get("data", {})
        print(f"Sending production update to client: {data}")
        await self.send(
            text_data=json.dumps(
                {
                    "type": "send_production_update",
                    "data": data,
                }
            )
        )
        print(
            f"Sent WebSocket message: {{'type': 'send_production_update', 'data': {data}}}"
        )


from django.utils import timezone
from .models import FormRequest


class FormRequestConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Create a group for the authenticated user
        self.user = self.scope["user"]
        if self.user.is_authenticated:
            self.group_name = f"user_{self.user.id}"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            # Send existing valid requests on connect
            await self.send_existing_requests()
        else:
            await self.close()

    async def disconnect(self, close_code):
        if self.user.is_authenticated:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # Handle any incoming messages from the client (optional)
        pass

    async def send_existing_requests(self):
        # Fetch valid requests for the user
        current_time = timezone.now().replace(second=0, microsecond=0)
        # Fetch the queryset with select_related and convert to list
        form_requests = await sync_to_async(list)(
            FormRequest.objects.filter(
                status="Accepted",
                checksheet__assigned_users=self.user,
                visible_until__gte=current_time,
            ).select_related(
                "checksheet"
            )  # Pre-fetch checksheet to avoid extra queries
        )
        # Process the list in async context
        requests = [
            {
                "id": req.id,
                "checksheet_aname": req.checksheet.name if req.checksheet else "N/A",
                "visible_until": req.visible_until.isoformat(),
            }
            for req in form_requests  # Regular for loop since it's a list
        ]
        await self.send(
            text_data=json.dumps({"type": "form_requests", "form_requests": requests})
        )

    async def form_request_update(self, event):
        # Send new or updated form request to the client
        await self.send(
            text_data=json.dumps(
                {"type": "form_requests", "form_requests": [event["request"]]}
            )
        )
