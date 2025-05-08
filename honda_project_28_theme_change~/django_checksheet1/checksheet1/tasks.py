from celery import shared_task
from datetime import date
import json
from .models import RejectionAlertConfig
from .views import send_sms


@shared_task
def send_rejection_alert_sms(rejection_count):
    config = RejectionAlertConfig.objects.first()
    if not config:
        return "No config found"

    try:
        numbers_data = config.phone_numbers
        if isinstance(numbers_data, str):
            numbers_data = json.loads(numbers_data)

        numbers = numbers_data.get("numbers", [])
        success = False

        for number in numbers:
            if number and send_sms(
                number,
                f"Alert: Rejection count {rejection_count} exceeded threshold {config.rejection_threshold}.",
            ):
                success = True

        if success:
            config.last_sms_sent = date.today()
            config.save()
            return "SMS sent and config updated"
        return "SMS not sent"

    except Exception as e:
        return f"Error during SMS sending: {str(e)}"
