import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_checksheet1.settings')

app = Celery('django_checksheet1')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()