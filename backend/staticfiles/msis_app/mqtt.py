import paho.mqtt.client as mqtt
import json
from .models import (
    Factory,
    Machine,
    User,
    DAirbag,
    DMold,
    DPcb,
    DPinArrival,
    DReelPackaging,
    Camera
)

# Define the MQTT on_message callback function
def on_message(client, userdata, msg):
    try:
        # Parse the incoming message payload
        data = json.loads(msg.payload)
        topic = msg.topic
        
        # Extract machine ID and camera ID from the topic
        topic_parts = topic.split('/')
        if len(topic_parts) < 4:
            print(f"Unexpected topic format: {topic}")
            return

        machine_id = topic_parts[2]  # Machine ID
        camera_id = topic_parts[3]   # Camera ID

        # Map machine ID to the corresponding Django model
        machine_model_map = {
            'mold': DMold,
            'airbag': DAirbag,
            'pcb': DPcb,
            'pinarrival': DPinArrival,
            'reelpackaging': DReelPackaging
        }
        
        # Determine model class based on machine ID prefix
        machine_type = machine_id.split('-')[0]
        model_class = machine_model_map.get(machine_type)
        if not model_class:
            print(f"Unknown machine type: {machine_type}")
            return

        # Extract data fields from the payload
        status = data.get('status')
        proc_time = data.get('proc_time')
        timestamp = data.get('timestamp')
        
        try:
            camera = Camera.objects.get(id=camera_id)
        except Camera.DoesNotExist:
            print(f"Camera with ID {camera_id} does not exist.")
            return
        
        # Create an entry in the corresponding model
        model_class.objects.create(
            camera=camera,
            status=status,
            proc_time=proc_time,
            timestamp=timestamp,
        )
    
    except Exception as e:
        print(f"Failed to process MQTT message: {str(e)}")

# Define the MQTT on_connect callback function
def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    
    # Subscribe to all topics dynamically for each machine type
    client.subscribe("smart_factory/message/mold-*/#")
    client.subscribe("smart_factory/message/airbag-*/#")
    client.subscribe("smart_factory/message/pcb-*/#")
    client.subscribe("smart_factory/message/pinarrival-*/#")
    client.subscribe("smart_factory/message/reelpackaging-*/#")

# Define the MQTT on_disconnect callback function
def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"Unexpected disconnection with code {rc}")
    else:
        print("Disconnected successfully.")

# Start the MQTT client and connect to the broker
def start_mqtt_client():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    broker_address = "100.115.26.20"  # broker address
    client.connect(broker_address, 1883, 60)
    client.loop_start()



