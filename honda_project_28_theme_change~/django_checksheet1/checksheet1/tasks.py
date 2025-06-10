# checksheet1/tasks.py
from celery import shared_task
from datetime import date
import json
from .models import RejectionAlertConfig
from .utils import send_sms  # Import from utils.py
from celery import shared_task
from datetime import date
import json
from .models import RejectionAlertConfig
# from .views import send_sms


@shared_task
def send_rejection_alert_sms(rejection_count, individual_threshold, phone_number, employee_id):
    config = RejectionAlertConfig.objects.first()
    if not config:
        return "No config found"

    try:
        if send_sms(
            phone_number,
            f"Alert for {employee_id}: Rejection count {rejection_count} exceeded your threshold of {individual_threshold}.",
        ):
            return f"SMS sent to {phone_number} for {employee_id}"
        return f"SMS not sent to {phone_number}"
    except Exception as e:
        return f"Error during SMS sending to {phone_number}: {str(e)}"

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import random
import string
from celery import shared_task
from .models import OTP, CustomUser
import logging

# Set up logging
logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_otp_email(self, user_id, employee_id):
    """
    Send OTP via email with retry mechanism
    """
    try:
        user = CustomUser.objects.get(id=user_id)
        
        # Generate OTP
        otp_code = ''.join(random.choices(string.digits, k=6))
        expires_at = timezone.now() + timedelta(minutes=10)
        
        # Clear any existing OTPs for this user
        OTP.objects.filter(user=user).delete()
        
        # Create new OTP
        OTP.objects.create(user=user, otp_code=otp_code, expires_at=expires_at)
        
        # Email content
        subject = 'Your OTP Code for Login'
        message = f"""
        Hello {user.username},
        
        Your One-Time Password (OTP) for login is: {otp_code}
        
        This OTP is valid for 10 minutes only.
        
        If you didn't request this OTP, please ignore this email.
        
        Best regards,
        Your Security Team
        """
        
        # Send email
        email = user.email
        
        # Create message
        msg = MIMEMultipart()
        msg["From"] = settings.SMTP_EMAIL
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))
        
        # Send via SMTP
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(settings.SMTP_EMAIL, settings.SMTP_APP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"OTP sent successfully to {email} for user {employee_id}")
        return f"OTP sent successfully to {email} for user {employee_id}"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User with ID {user_id} not found")
        return f"User with ID {user_id} not found"
        
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending OTP to user {employee_id}: {str(e)}")
        # Retry the task
        raise self.retry(exc=e, countdown=60, max_retries=3)
        
    except Exception as e:
        logger.error(f"Unexpected error in send_otp_email task for user {employee_id}: {str(e)}")
        # Retry for unexpected errors too
        try:
            raise self.retry(exc=e, countdown=60, max_retries=3)
        except self.MaxRetriesExceededError:
            logger.error(f"Max retries exceeded for sending OTP to user {employee_id}")
            return f"Failed to send OTP after maximum retries: {str(e)}"

@shared_task
def cleanup_expired_otps():
    """
    Cleanup expired OTPs - run this periodically
    """
    try:
        expired_count = OTP.objects.filter(expires_at__lt=timezone.now()).count()
        OTP.objects.filter(expires_at__lt=timezone.now()).delete()
        logger.info(f"Cleaned up {expired_count} expired OTPs")
        return f"Cleaned up {expired_count} expired OTPs"
    except Exception as e:
        logger.error(f"Error cleaning up expired OTPs: {str(e)}")
        return f"Error cleaning up expired OTPs: {str(e)}"