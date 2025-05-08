from django.contrib.auth.decorators import login_required
from .models import PageAccess

from django.contrib.auth.models import AnonymousUser


def has_page_access(user, page_name=""):
    if isinstance(user, AnonymousUser) or not user.is_authenticated:
        return False  # Return False if the user is not logged in

    if not page_name:
        return False  # Ensure page_name is provided

    return PageAccess.objects.filter(user=user, page_name=page_name).exists()


from .models import PasswordResetRequest


def pending_requests_count(request):
    if request.user.is_authenticated and request.user.role == "admin":
        count = PasswordResetRequest.objects.filter(status="pending").count()
        return {"pending_requests_count": count}
    return {}
