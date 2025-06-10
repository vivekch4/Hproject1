from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta, date
import json
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import FilledCheckSheet, RejectionAlertConfig, ProductionDb, FormRequest
from .views import (

    broadcast_production_update,
)  # Consider moving this to utils.py if reused elsewhere
from .utils import send_sms
from .tasks import send_rejection_alert_sms
from .models import CustomUser

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

        if status and isinstance(status, dict) and status.get("completely_reject", False):
            rejection_count += 1

    recipients = config.get_alert_recipients()
    # Sort recipients by percentage to process in ascending order
    recipients = sorted(recipients, key=lambda x: float(x.get("percentage", 0)))

    today_str = date.today().strftime("%Y-%m-%d")
    for recipient in recipients:
        percentage = float(recipient.get("percentage", 0))
        user_id = recipient.get("user_id")
        phone_number = recipient.get("phone_number")
        last_sms_sent = recipient.get("last_sms_sent")
        individual_threshold = int(config.rejection_threshold * (percentage / 100.0))

        # Skip if already sent today or threshold not reached
        if last_sms_sent == today_str or rejection_count < individual_threshold:
            continue

        # Check if this is the first threshold crossed
        is_first_crossed = True
        for other_recipient in recipients:
            other_percentage = float(other_recipient.get("percentage", 0))
            other_threshold = int(config.rejection_threshold * (other_percentage / 100.0))
            other_last_sent = other_recipient.get("last_sms_sent")
            if other_percentage < percentage and rejection_count >= other_threshold and other_last_sent != today_str:
                is_first_crossed = False
                break

        if is_first_crossed:
            try:
                user = CustomUser.objects.get(id=user_id)
                send_rejection_alert_sms.delay(
                    rejection_count,
                    individual_threshold,
                    phone_number,
                    user.employee_id
                )
                config.update_recipient_sms_sent(user_id, date.today())
                break  # Stop after sending to the first eligible recipient
            except CustomUser.DoesNotExist:
                continue
            
            
@receiver(post_save, sender=ProductionDb)
@receiver(post_save, sender=FilledCheckSheet)
def trigger_production_update(sender, instance, created, **kwargs):
    print(f"Signal connected and triggered for {sender.__name__} (created: {created}) with instance: {instance}")
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
