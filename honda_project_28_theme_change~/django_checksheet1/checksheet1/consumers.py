import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from .models import CheckSheet, FilledCheckSheet,ProductionDb
from asgiref.sync import sync_to_async

class ProductionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print(f"WebSocket connected: {self.channel_name}")
        self.selected_date = None
        await self.channel_layer.group_add("production_group", self.channel_name)
        await self.accept()
        await self.send(text_data=json.dumps({"message": "Connected to WebSocket"}))
        print("Sent connection confirmation to client")

    async def disconnect(self, close_code):
        print(f"WebSocket disconnected: {close_code}")
        await self.channel_layer.group_discard("production_group", self.channel_name)

    async def receive(self, text_data):
        print(f"Received WebSocket message: {text_data}")
        try:
            data = json.loads(text_data)
            print(f"Parsed WebSocket data: {data}")
            if data.get('type') == 'set_date_filter':
                try:
                    selected_date = data.get('date')
                    print(f"Received date filter: {selected_date}")
                    if selected_date:
                        selected_date = timezone.datetime.strptime(selected_date, '%Y-%m-%d')
                        self.selected_date = timezone.make_aware(selected_date, timezone.get_current_timezone())
                        print(f"Set date filter to: {self.selected_date}")
                    else:
                        self.selected_date = None
                        print("Cleared date filter")
                    production_data = await self.get_production_data()
                    print(f"Production data for date: {production_data}")
                    await self.send_production_update({'data': production_data})
                except ValueError as ve:
                    print(f"Invalid date format: {ve}")
                    await self.send(text_data=json.dumps({
                        'type': 'error',
                        'message': 'Invalid date format'
                    }))
                except Exception as e:
                    print(f"Error processing date filter: {e}")
                    await self.send(text_data=json.dumps({
                        'type': 'error',
                        'message': 'Error processing date filter'
                    }))
            else:
                print(f"Unknown message type: {data.get('type')}")
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'Unknown message type'
                }))
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            print(f"Unexpected error in receive: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'An error occurred processing your request'
            }))

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
        print(f"Sent WebSocket message: {{'type': 'send_production_update', 'data': {data}}}")

    async def get_production_data(self):
        # Determine date range
        if self.selected_date:
            start_date = self.selected_date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = start_date + timezone.timedelta(days=1, microseconds=-1)
        else:
            today = timezone.now()
            start_date = today.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = start_date + timezone.timedelta(days=1, microseconds=-1)

        print(f"Fetching production data for {start_date} to {end_date}")

        # Fetch data using sync_to_async for synchronous database operations
        @sync_to_async
        def fetch_production_data():
            try:
                checksheets = CheckSheet.objects.all()
                filled_sheets = FilledCheckSheet.objects.filter(
                    checksheet__in=checksheets, timestamp__gte=start_date, timestamp__lte=end_date
                )
                print(f"Found {filled_sheets.count()} filled sheets for {start_date} to {end_date}")

                total_rejects = 0

                # Count rejects from filled sheets
                for filled in filled_sheets:
                    status_data = filled.status_data
                    for key, value in status_data.items():
                        if key == "completely_reject" and value == "Yes":
                            total_rejects += 1

                # Get total production from last ProductionDb entry for the date
                try:
                    last_production = ProductionDb.objects.filter(
                        timestamp__gte=start_date,
                        timestamp__lte=end_date
                    ).latest('timestamp')
                    total_production = int(last_production.Production_count)
                except ProductionDb.DoesNotExist:
                    total_production = 0

                # Calculate actual production
                actual_production = total_production - total_rejects

                efficiency = (
                    (actual_production / total_production * 100) if total_production > 0 else 0
                )

                return {
                    'production_count': total_production,
                    'total_rejects': total_rejects,
                    'actual_production': actual_production,
                    'efficiency': f"{efficiency:.2f}%",
                }
            except Exception as e:
                print(f"Error in fetch_production_data: {e}")
                return {
                    'production_count': 'N/A',
                    'total_rejects': 'N/A',
                    'actual_production': 'N/A',
                    'efficiency': 'N/A',
                }

        try:
            return await fetch_production_data()
        except Exception as e:
            print(f"Error fetching production data: {e}")
            return {
                'production_count': 'N/A',
                'total_rejects': 'N/A',
                'actual_production': 'N/A',
                'efficiency': 'N/A',
            }

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
