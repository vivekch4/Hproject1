from django import template
from checksheet1.models import PageAccess

register = template.Library()


@register.filter
def has_page_access(user, page_name):
    if user.is_authenticated and user.role == "admin":
        return True  # Admin has all access

    return PageAccess.objects.filter(
        user=user, page_name=page_name, has_access=True
    ).exists()


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, {})


@register.filter
def to_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


import pytz



@register.filter
def to_ist(value):
    if not value:
        return value
    # Assuming value is a datetime object
    utc_time = value
    if utc_time.tzinfo is None:
        # Make it timezone-aware if it's naive
        utc_time = pytz.utc.localize(utc_time)
    ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
    return ist_time.strftime('%Y-%m-%d %H:%M:%S')