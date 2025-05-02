# checksheet1/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer

class ProductionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print(f'WebSocket connected: {self.channel_name}')
        await self.channel_layer.group_add('production_group', self.channel_name)
        await self.accept()
        await self.send(text_data=json.dumps({'message': 'Connected to WebSocket'}))
        print('Sent connection confirmation to client')

    async def disconnect(self, close_code):
        print(f'WebSocket disconnected: {close_code}')
        await self.channel_layer.group_discard('production_group', self.channel_name)

    async def send_production_update(self, event):
        print(f"Received event in consumer: {event}")
        data = event.get("data", {})
        print(f"Sending production update to client: {data}")
        await self.send(text_data=json.dumps({
            "type": "send_production_update",
            "data": data,
        }))
        print(f"Sent WebSocket message: {{'type': 'send_production_update', 'data': {data}}}")