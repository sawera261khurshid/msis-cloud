from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
# from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cloud_project.settings')  

app = Celery('msis_app')

# Load task modules from all registered Django apps.
app.autodiscover_tasks(['msis_app'])

# Schedule the task to run every minute for testing
# app.conf.beat_schedule = {
#     'update-factory-reset-timestamps': {
#         'task': 'msis_app.tasks.update_factory_reset_timestamps',
#         'schedule': crontab(minute='*'),  # Runs every minute for testing
#     },
# }

# app.conf.beat_schedule = {
#     'update-factory-reset-timestamps': {
#         'task': 'msis_app.tasks.update_factory_reset_timestamps',
#         'schedule': crontab(minute='*/5'),  # Every 5 minutes
#     },
# }

CELERY_BEAT_SCHEDULE = {
    'reset-factory-counts-every-day': {
        'task': 'msis_app.tasks.automatic_factory_reset_8am_and_8pm',  
        'schedule': crontab(hour='8,20', minute='0'),  # Every day at 8 AM and 8 PM
    },
}


# Optional: Configure Celery
# app.conf.timezone = 'UTC'  # Set to your desired timezone if needed
