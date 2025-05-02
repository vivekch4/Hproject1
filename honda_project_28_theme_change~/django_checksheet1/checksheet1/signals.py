from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta, date
import json


from .models import FilledCheckSheet, RejectionAlertConfig,ProductionDb
from .views import send_sms,broadcast_production_update  # Consider moving this to utils.py if reused elsewhere

@receiver(post_save, sender=FilledCheckSheet)
def check_rejections_on_save(sender, instance, created, **kwargs):
    print("Signal triggered!")
    config = RejectionAlertConfig.objects.first()
    if not config:
        return

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    tomorrow = today_start + timedelta(days=1)

    # Count today's rejections
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
        if "completely_reject" in status:
            rejection_count += 1

    # Check if threshold is crossed and no SMS sent today
    if rejection_count >= config.rejection_threshold:
        if config.last_sms_sent != date.today():
            numbers_data = config.phone_numbers
            if isinstance(numbers_data, str):
                numbers_data = json.loads(numbers_data)

            numbers = numbers_data.get("numbers", [])
            for number in numbers:
                if number:
                    send_sms(number, f"Alert: Rejection count {rejection_count} exceeded threshold {config.rejection_threshold}.")

            # Update last_sms_sent_date
            config.last_sms_sent = date.today()
            config.save()



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