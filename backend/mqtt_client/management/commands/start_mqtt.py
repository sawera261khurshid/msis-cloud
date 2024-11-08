from django.core.management.base import BaseCommand
from mqtt_client.mqtt_service import start_mqtt_client  

class Command(BaseCommand):
    help = 'Start the MQTT client'

    def handle(self, *args, **options):
        self.stdout.write("Starting MQTT client...")
        try:
            start_mqtt_client()  # Call the function to start the MQTT client
            self.stdout.write(self.style.SUCCESS("MQTT client started successfully."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to start MQTT client: {e}"))
