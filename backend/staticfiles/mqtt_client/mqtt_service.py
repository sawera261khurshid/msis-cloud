# mqtt_client/mqtt_service.py
import logging
import json
import paho.mqtt.client as mqtt
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from msis_app.models import (
    Machine,
    DAirbag,
    DMold,
    DPcb,
    DPinArrival,
    DReelPackaging,
    Camera
)

machines = []
topic = "smartfactory/message"
client = None

# Get the logger
logger = logging.getLogger('mqtt_client')

def on_connect(client, userdata, flags, rc):
    global machines
    logger.info(f"Connected with result code {rc}")
    
    machines = Machine.objects.filter(is_deleted=False).values_list('name', flat=True)
    machines = list(machines)
    
    # Subscribe to all topics dynamically for each machine type
    try:
        for machine in machines:
            client.subscribe(f"{topic}/{machine}/#")
            logger.info(f"Subscribed to topic: {topic}/{machine}/#")
    except ValueError as e:
        logger.error(f"Subscription failed with error: {e}")

def add_subscription(sub_topic):
    try:
        if client:
            client.subscribe(f"{topic}/{sub_topic}")
            print(f"Subscribed to a new topic: {topic}/{sub_topic}")
    except ValueError as e:
        logger.error(f"Subscription failed with error: {e}")

def remove_subscription(sub_topic):
    try:
        if client:
            client.unsubscribe(f"{topic}/{sub_topic}")
            print(f"Unsubscribed from topic: {topic}/{sub_topic}")
    except ValueError as e:
        logger.error(f"Unsubscribing failed with error: {e}")

def on_message(client, userdata, msg):
    global machines
    try:
        payload_str = msg.payload.decode()
        payload = json.loads(payload_str)
        # logger.debug(f"Received message: {payload} on topic {msg.topic} with QoS {msg.qos}")
        # Extract values from the payload
        stt_ = payload.get('stt')
        proc_time = payload.get('proc_time')
        camera_refid = payload.get("det", {}).get("refid")
        status = str(stt_) if stt_ is not None else None
        status = 'NG' if '12' in status else 'Normal'
        machine_name = msg.topic.rsplit('/')[2]
        camera_name = msg.topic.rsplit('/')[-1]
        machine = ""
        camera = ""
        # logger.debug(f"camera id: {camera_refid}, camera_name: {camera_name}, machine: {machine_name}, status: {status}")
        try:
            machine = Machine.objects.get(name=machine_name)
            # camera = Camera.objects.get(id=camera_refid)
            camera = Camera.objects.filter(name=camera_name, machine=machine).first()
        except Camera.DoesNotExist as e:
            logger.error(f"Camera with id {camera_refid} does not exist. Error: {e}, msg topic: {msg.topic}")
            return
        except ObjectDoesNotExist as e:
            logger.error(f"Error fetching camera: {e}, msg.topic: {msg.topic}")
            return
        except Machine.DoesNotExist as e:
            logger.error(f"Machine with name {machine_name} does not exist. Error: {e}, msg.topic: {msg.topic}")
            return

        # Save a new record
        if 'mold' in machine_name :
            trigger_similarity = payload.get('trigger_matching_similarity')
            trigger_similarity_0 = trigger_similarity.get('0') if trigger_similarity else None
            trigger_similarity_1 = trigger_similarity.get('1') if trigger_similarity else None
            DMold.objects.create(
                status=str(status) if status is not None else None,
                trigger_similarity_0=trigger_similarity_0,
                trigger_similarity_1=trigger_similarity_1,
                proc_time=proc_time,
                camera=camera,
                machine=machine
            )
        elif 'airbag' in machine_name:
            DAirbag.objects.create(
                status=str(status) if status is not None else None,
                proc_time=proc_time,
                camera=camera,
                machine=machine
            )
        elif 'reel-packaging' in machine_name:
            DReelPackaging.objects.create(
                status=str(status) if status is not None else None,
                proc_time=proc_time,
                camera=camera,
                machine=machine
            )
        elif 'pcb' in machine_name:
            trigger_similarity = payload.get('trigger_matching_similarity')
            trigger_similarity_0 = trigger_similarity.get('0') if trigger_similarity else None
            trigger_similarity_1 = trigger_similarity.get('1') if trigger_similarity else None
            DPcb.objects.create(
                status=str(status) if status is not None else None,
                trigger_similarity_0=trigger_similarity_0,
                trigger_similarity_1=trigger_similarity_1,
                proc_time=proc_time,
                camera=camera,
                machine=machine
            )
        elif 'pin' in machine_name:
            DPinArrival.objects.create(
                status=str(status) if status is not None else None,
                proc_time=proc_time,
                camera=camera,
                machine=machine
            )
        else:
            logger.warning(f"\nWrong machine data was retrieved from mqtt, msg.topic: {msg.topic}!!!\n")

    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from MQTT message: {e}, msg.topic: {msg.topic}")
    except Exception as e:
        logger.error(f"An error occurred: {e}, msg.topic: {msg.topic}")

def on_disconnect(client, userdata, rc):
    logger.info(f"Disconnected with result code {rc}. Reconnecting...")
    if rc != 0:
        client.reconnect()

def start_mqtt_client():
    global client

    if client is None:
        logger.info('Started mqtt client. Connecting...')
        client = mqtt.Client()
        # client.on_connect = on_connect
        # client.on_message = on_message

        # # Connect to the broker (you can use settings from Django settings)
        # broker_url = settings.MQTT_BROKER_URL
        # broker_port = settings.MQTT_BROKER_PORT
        # client.connect(broker_url, broker_port, 60)
        # logger.info(f'Connected to broker at: {settings.MQTT_BROKER_URL}')

        # # Start the loop in a non-blocking way
        # client.loop_start()
    else:
        logger.info("MQTT is already connected.")

# logger.debug("Debug message from MQTT client.")