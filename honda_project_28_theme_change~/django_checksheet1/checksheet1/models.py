from django.db import models
from django.conf import settings
from datetime import datetime
from django.contrib.auth.models import AbstractUser
import os
from django.core.serializers.json import DjangoJSONEncoder

import json
import re

def current_datetime():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


class CheckSheet(models.Model):
    name = models.CharField(max_length=255)
    line = models.CharField(
        max_length=10, choices=[("line_1", "Line 1"), ("line_2", "Line 2")]
    )
    assigned_users = models.ManyToManyField(
        "CustomUser", related_name="assigned_check_sheets", blank=True
    )
    created_by = models.ForeignKey(
        "CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_check_sheets",
    )
    created_on = models.DateTimeField(auto_now_add=True)

    # Designated approvers for each level
    level_1_approver = models.ForeignKey(
        "CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_1_assigned_checksheets",
    )

    level_2_approver = models.ForeignKey(
        "CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_2_assigned_checksheets",
    )

    require_level_3_approval = models.BooleanField(
        default=True, help_text="Check if this sheet requires Level 3 approval (admin)"
    )

    def __str__(self):
        return self.name


class CheckSheetImage(models.Model):
    checksheet = models.ForeignKey(
        CheckSheet, on_delete=models.CASCADE, related_name="images"
    )
    image = models.ImageField(upload_to="checksheet_images/")

    def __str__(self):
        return f"{self.checksheet.name} - Image {self.id}"


class Zone(models.Model):
    INPUT_TYPE_CHOICES = [
        ("int", "Integer"),
        ("float", "Float"),
        ("checkbox", "Checkbox"),
    ]

    checksheet = models.ForeignKey(
        CheckSheet, on_delete=models.CASCADE, related_name="zones"
    )
    name = models.CharField(max_length=255)
    input_type = models.CharField(
        max_length=10, choices=INPUT_TYPE_CHOICES, default="int"
    )

    def __str__(self):
        return f"{self.checksheet.name} - {self.name} ({self.input_type})"


class StarterSheet(models.Model):
    name = models.CharField(max_length=255)
    line = models.CharField(
        max_length=10, choices=[("line_1", "Line 1"), ("line_2", "Line 2")]
    )
    assigned_users = models.ManyToManyField(
        "CustomUser", related_name="assigned_starter_sheets", blank=True
    )
    created_by = models.ForeignKey(
        "CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_starter_sheets",
    )
    created_on = models.DateTimeField(auto_now_add=True)

    # Designated approvers for each level
    level_1_approver = models.ForeignKey(
        "CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_1_assigned_sheets",
    )

    level_2_approver = models.ForeignKey(
        "CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_2_assigned_sheets",
    )

    require_level_3_approval = models.BooleanField(
        default=True, help_text="Check if this sheet requires Level 3 approval (admin)"
    )

    def __str__(self):
        return self.name


class StarterZone(models.Model):
    startersheet = models.ForeignKey(
        StarterSheet, on_delete=models.CASCADE, related_name="zones"
    )
    name = models.CharField(max_length=255)
    type = models.CharField(
        max_length=20,
        choices=[("int", "Integer"), ("float", "Float"), ("checkbox", "Checkbox")],
    )
    min_value = models.CharField(null=True, blank=True, max_length=255)
    max_value = models.CharField(null=True, blank=True, max_length=255)
    unit = models.CharField(max_length=50, null=True, blank=True)  # New field for unit
    check_method = models.TextField(null=True, blank=True)  # New field for check method
    image = models.ImageField(upload_to="zone_images/", null=True, blank=True)
    standard = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"{self.startersheet.name} - {self.name}"


class FilledCheckSheet(models.Model):
    APPROVAL_STATUS_CHOICES = [
        ("pending", "Pending Level 1 Approval"),
        ("level_1_approved", "Level 1 Approved"),
        ("level_2_approved", "Level 2 Approved"),
        ("level_3_approved", "Level 3 Approved"),
        ("completed", "Completed"),
        ("rejected", "Rejected"),
    ]

    checksheet = models.ForeignKey(CheckSheet, on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE
    )  # Add user field
    status_data = models.JSONField(
        default=dict
    )  # Store all zone statuses in JSON format
    timestamp = models.DateTimeField(default=current_datetime, blank=True, null=True)
    shift = models.CharField(
        max_length=1, choices=[("A", "Shift A"), ("B", "Shift B"), ("C", "Shift C")]
    )
    line = models.CharField(max_length=100, blank=True, null=True)

    # Approval status
    approval_status = models.CharField(
        max_length=20,
        choices=APPROVAL_STATUS_CHOICES,
        default="pending",
    )

    # Designated approvers (these need to be copied from CheckSheet when created)
    assigned_level_1_approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_level_1_checksheets",
    )

    assigned_level_2_approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_level_2_checksheets",
    )

    requires_level_3_approval = models.BooleanField(default=True)

    # Track each approver action
    level_1_approval = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_1_approved_checksheets",
    )
    level_1_approval_timestamp = models.DateTimeField(null=True, blank=True)

    level_2_approval = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_2_approved_checksheets",
    )
    level_2_approval_timestamp = models.DateTimeField(null=True, blank=True)

    level_3_approval = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_3_approved_checksheets",
    )
    level_3_approval_timestamp = models.DateTimeField(null=True, blank=True)

    # For storing rejection information
    rejected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="rejected_checksheets",
    )
    rejection_timestamp = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True, null=True)

    # Stores if acknowledgment is needed
    send_acknowledgment = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.checksheet.name} - {self.user.username} ({self.timestamp})"

    def get_current_approval_level(self):
        """Return which approval level this sheet is currently at"""
        if self.approval_status == "pending":
            return 1
        elif self.approval_status == "level_1_approved":
            return 2
        elif (
            self.approval_status == "level_2_approved"
            and self.requires_level_3_approval
        ):
            return 3
        else:
            return None  # Already fully approved or rejected

    def can_approve(self, user):
        """Check if the given user can approve this sheet at its current state"""
        current_level = self.get_current_approval_level()

        if current_level == 1 and self.assigned_level_1_approver == user:
            return True
        elif current_level == 2 and self.assigned_level_2_approver == user:
            return True
        elif current_level == 3 and user.role == "admin":
            return True
        return False

    def save(self, *args, **kwargs):
        # If this is a new record, copy the designated approvers from the check sheet
        if not self.pk:
            if hasattr(self, "checksheet") and self.checksheet:
                self.assigned_level_1_approver = self.checksheet.level_1_approver
                self.assigned_level_2_approver = self.checksheet.level_2_approver
                self.requires_level_3_approval = (
                    self.checksheet.require_level_3_approval
                )

        super().save(*args, **kwargs)


class PasswordResetRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    requested_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=[("pending", "Pending"), ("approved", "Approved")],
        default="pending",
    )
    new_password = models.CharField(
        max_length=128, blank=True, null=True
    )  # Admin sets this

    def __str__(self):
        return f"{self.user.employee_id} - {self.status}"


class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ("admin", "Admin"),
        ("quality_incharge", "Quality Incharge"),
        ("shift_incharge", "Shift Incharge"),
        ("operator", "Operator"),
    ]
    username = models.CharField(max_length=150, unique=False)
    employee_id = models.CharField(max_length=20, unique=True)  # New field
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="admin")
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    USERNAME_FIELD = "employee_id"  # Use employee_id for authentication
    REQUIRED_FIELDS = ["username", "email"]  # Keep username for internal use

    def __str__(self):
        return f"{self.employee_id} ({self.role})"


def poc_upload_path(instance, filename):
    # This will return something like 'poc_pdfs/process.pdf'
    return os.path.join("poc_pdfs", filename)


class POCUpload(models.Model):
    pdf = models.FileField(upload_to=poc_upload_path)
    assigned_startersheets = models.ManyToManyField(
        StarterSheet,
        related_name="assigned_pocs",
        blank=True,
    )

    def __str__(self):
        return f"POC Upload - {self.pdf.name}"


class Field(models.Model):
    startersheet = models.ForeignKey(
        StarterSheet, related_name="fields", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    field_type = models.CharField(
        max_length=50, choices=[("text", "Text"), ("image", "Image")]
    )

    def __str__(self):
        return f"{self.name} ({self.field_type})"


class FilledStarterSheet(models.Model):
    APPROVAL_STATUS_CHOICES = [
        ("pending", "Pending Level 1 Approval"),
        ("level_1_approved", "Level 1 Approved"),
        ("level_2_approved", "Level 2 Approved"),
        ("level_3_approved", "Level 3 Approved"),
        ("completed", "Completed"),
        ("rejected", "Rejected"),
    ]

    startersheet = models.ForeignKey(StarterSheet, on_delete=models.CASCADE)
    filled_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status_data = models.JSONField(
        default=dict
    )  # Store all zone statuses in JSON format
    timestamp = models.DateTimeField(auto_now_add=True)
    shift = models.CharField(
        max_length=1, choices=[("A", "Shift A"), ("B", "Shift B"), ("C", "Shift C")]
    )
    line = models.CharField(max_length=100, blank=True, null=True)
    out_of_range_reason = models.TextField(blank=True, null=True)
    # Approval status
    approval_status = models.CharField(
        max_length=20,
        choices=APPROVAL_STATUS_CHOICES,
        default="pending",
    )

    # Designated approvers (copied from StarterSheet when created)
    assigned_level_1_approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_level_1_sheets",
    )

    assigned_level_2_approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_level_2_sheets",
    )

    requires_level_3_approval = models.BooleanField(default=True)

    # Track each approver action
    level_1_approval = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_1_approved_sheets",
    )
    level_1_approval_timestamp = models.DateTimeField(null=True, blank=True)

    level_2_approval = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_2_approved_sheets",
    )
    level_2_approval_timestamp = models.DateTimeField(null=True, blank=True)

    level_3_approval = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="level_3_approved_sheets",
    )
    level_3_approval_timestamp = models.DateTimeField(null=True, blank=True)

    # For storing rejection information
    rejected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="rejected_sheets",
    )
    rejection_timestamp = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return (
            f"{self.startersheet.name} - {self.filled_by.username} ({self.timestamp})"
        )

    def get_current_approval_level(self):
        """Return which approval level this sheet is currently at"""
        if self.approval_status == "pending":
            return 1
        elif self.approval_status == "level_1_approved":
            return 2
        elif (
            self.approval_status == "level_2_approved"
            and self.requires_level_3_approval
        ):
            return 3
        else:
            return None  # Already fully approved or rejected

    def can_approve(self, user):
        """Check if the given user can approve this sheet at its current state"""
        current_level = self.get_current_approval_level()

        if current_level == 1 and self.assigned_level_1_approver == user:
            return True
        elif current_level == 2 and self.assigned_level_2_approver == user:
            return True
        elif current_level == 3 and user.role == "admin":
            return True
        return False

    def save(self, *args, **kwargs):
        # If this is a new record, copy the designated approvers from the starter sheet
        if not self.pk:
            if hasattr(self, "startersheet") and self.startersheet:
                self.assigned_level_1_approver = self.startersheet.level_1_approver
                self.assigned_level_2_approver = self.startersheet.level_2_approver
                self.requires_level_3_approval = (
                    self.startersheet.require_level_3_approval
                )

        super().save(*args, **kwargs)


class PageAccess(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    page_name = models.CharField(max_length=100)  # Page or Function Name
    has_access = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.page_name} ({'Allowed' if self.has_access else 'Denied'})"


from django.utils.timezone import make_aware


class FormRequest(models.Model):
    checksheet = models.ForeignKey(
        CheckSheet, on_delete=models.CASCADE, related_name="form_requests"
    )
    shift = models.CharField(
        max_length=1,
        choices=[("A", "Shift A"), ("B", "Shift B"), ("C", "Shift C")],
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="form_requests"
    )
    line = models.CharField(max_length=50, blank=True, null=True)
    date = models.DateField()
    reason = models.TextField()
    status = models.CharField(
        max_length=10,
        choices=[
            ("Pending", "Pending"),
            ("Accepted", "Accepted"),
            ("Rejected", "Rejected"),
        ],
        default="Pending",
    )
    created_at = models.DateTimeField(default=current_datetime, blank=True, null=True)
    visible_until = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.checksheet.name} - {self.checksheet.assigned_users.first()} - {self.date}"

    def save(self, *args, **kwargs):
        if self.visible_until and not self.visible_until.tzinfo:
            self.visible_until = make_aware(self.visible_until)  # Convert to UTC
        super().save(*args, **kwargs)


class ProductionDb(models.Model):
    Production_count = models.CharField(max_length=10)  # Define max length
    timestamp = models.DateTimeField()

    def __str__(self):
        return f"{self.Production_count} at {self.timestamp}"


class POCReadStatus(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    poc = models.ForeignKey(POCUpload, on_delete=models.CASCADE)
    read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.poc.pdf.name} - {'Read' if self.read else 'Unread'}"


class Shifttime(models.Model):
    shift_A_start = models.TimeField()
    shift_A_end = models.TimeField()
    shift_B_start = models.TimeField()
    shift_B_end = models.TimeField()

    def __str__(self):
        return f"Shift A: {self.shift_A_start}-{self.shift_A_end}, Shift B: {self.shift_B_start}-{self.shift_B_end}"
    
    
class RejectionAlertConfig(models.Model):
    rejection_threshold = models.IntegerField(default=2)
    # Store user IDs, phone numbers, percentages, and last_sms_sent as JSON
    alert_recipients = models.JSONField(encoder=DjangoJSONEncoder, default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @staticmethod
    def format_phone_number(phone):
        if not phone:
            return ""
        clean_number = re.sub(r"[^\d+]", "", phone)
        if not clean_number.startswith("+"):
            if len(clean_number) == 10:
                clean_number = "+91" + clean_number
            else:
                clean_number = "+" + clean_number
        return clean_number

    def get_alert_recipients(self):
        """Return alert recipients as a list of dictionaries"""
        if isinstance(self.alert_recipients, str):
            recipients = json.loads(self.alert_recipients)
        else:
            recipients = self.alert_recipients.get("recipients", [])
        return recipients

    def set_alert_recipients(self, recipients_list):
        """Set alert recipients from a list of dictionaries, ensuring proper formatting"""
        formatted_recipients = []
        for recipient in recipients_list:
            formatted_recipient = {
                "user_id": recipient.get("user_id"),
                "phone_number": self.format_phone_number(recipient.get("phone_number")),
                "percentage": float(recipient.get("percentage", 0)),
                "last_sms_sent": recipient.get("last_sms_sent")  # Preserve or initialize
            }
            formatted_recipients.append(formatted_recipient)
        self.alert_recipients = {"recipients": formatted_recipients}

    def update_recipient_sms_sent(self, user_id, sent_date):
        """Update last_sms_sent for a specific recipient"""
        recipients = self.get_alert_recipients()
        for recipient in recipients:
            if recipient.get("user_id") == user_id:
                recipient["last_sms_sent"] = sent_date.strftime("%Y-%m-%d")
        self.set_alert_recipients(recipients)
        self.save()

    def __str__(self):
        return f"Alert Config: {self.rejection_threshold} rejections, {len(self.get_alert_recipients())} recipients"


    

class ProductionTarget(models.Model):
    target_value = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Production Target: {self.target_value}"
    
    
    
class RejectReason(models.Model):
    reason = models.CharField(max_length=255, unique=True)
    

    def __str__(self):
        return self.reason    
from django.utils import timezone
    
class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)  # Add this field

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"OTP {self.otp_code} for {self.user.username}"

    class Meta:
        ordering = ['-created_at']