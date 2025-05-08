from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta, date
import json
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import FilledCheckSheet, RejectionAlertConfig, ProductionDb, FormRequest
from .views import (
    send_sms,
    broadcast_production_update,
)  # Consider moving this to utils.py if reused elsewhere

from .tasks import send_rejection_alert_sms


@receiver(post_save, sender=FilledCheckSheet)
def check_rejections_on_save(sender, instance, created, **kwargs):
    config = RejectionAlertConfig.objects.first()
    if not config:
        return

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    tomorrow = today_start + timedelta(days=1)

    rejection_count = 0
    checksheets = FilledCheckSheet.objects.filter(
        timestamp__gte=today_start, timestamp__lt=tomorrow
    )

    for sheet in checksheets:
        status = sheet.status_data
        if isinstance(status, str):
            try:
                status = json.loads(status)
            except json.JSONDecodeError:
                continue

        if (
            status
            and isinstance(status, dict)
            and status.get("completely_reject", False)
        ):
            rejection_count += 1

    if (
        rejection_count >= config.rejection_threshold
        and config.last_sms_sent != date.today()
    ):
        # Send SMS in the background
        send_rejection_alert_sms.delay(rejection_count)


@receiver(post_save, sender=ProductionDb)
@receiver(post_save, sender=FilledCheckSheet)
def trigger_production_update(sender, instance, created, **kwargs):
    print(
        f"Signal connected and triggered for {sender.__name__} (created: {created}) with instance: {instance}"
    )
    print(f"Calling broadcast_production_update for {sender.__name__}")
    try:
        broadcast_production_update()
        print("broadcast_production_update called successfully")
    except Exception as e:
        print(f"Error calling broadcast_production_update: {str(e)}")


@receiver(post_save, sender=FormRequest)
def form_request_saved(sender, instance, created, **kwargs):
    if instance.status == "Accepted":
        channel_layer = get_channel_layer()
        current_time = timezone.now().replace(second=0, microsecond=0)
        if instance.visible_until and instance.visible_until >= current_time:
            # Send to all assigned users
            for user in instance.checksheet.assigned_users.all():
                group_name = f"user_{user.id}"
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        "type": "form_request_update",
                        "request": {
                            "id": instance.id,
                            "checksheet_aname": (
                                instance.checksheet.name
                                if instance.checksheet
                                else "N/A"
                            ),
                            "visible_until": instance.visible_until.isoformat(),
                        },
                    },
                )
