from .models import Notification


def notify(user, notification_type, title, message="", link=""):
    if user is None:
        return None
    return Notification.objects.create(
        user=user, notification_type=notification_type, title=title, message=message, link=link
    )
