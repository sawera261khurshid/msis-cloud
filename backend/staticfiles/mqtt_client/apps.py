from django.apps import AppConfig
import logging
logger = logging.getLogger('mqtt_client')

class MqttClientConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'mqtt_client'

    def ready(self):
        # Import and start the MQTT client here
        logger.debug("MqttClientConfig is ready.")
        from .mqtt_service import start_mqtt_client
        start_mqtt_client()
