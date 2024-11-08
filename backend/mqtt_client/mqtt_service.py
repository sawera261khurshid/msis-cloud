# mqtt_client/mqtt_service.py
import logging
import sys
import json
import time
from datetime import timedelta

import paho.mqtt.client as mqtt
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from msis_app.models import (
    Machine,
    DAirbag,
    DMold,
    DPcb,
    DPinArrival,
    DReelPackaging,
    Camera,
    MqttClientState
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


last_msg = None
new_msg = None


def on_message(client, userdata, msg):
    global machines, last_msg, new_msg
    try:
        # msg_received_time = timezone.now()
        payload_str = msg.payload.decode()
        payload = json.loads(payload_str)
        logger.debug(f"Received message: {payload} on topic {msg.topic} with QoS {msg.qos}")
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
        logger.debug(f"camera id: {camera_refid}, camera_name: {camera_name}, machine: {machine_name}, status: {status}")
        try:
            machine = Machine.objects.get(name=machine_name)
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

        # Check for duplicates and save the new record
        time_threshold = timezone.now() - timedelta(seconds=1)
        if 'mold' in machine_name:
            existing_record = DMold.objects.filter(proc_time=proc_time, camera=camera, machine=machine,
                                                   status=status, timestamp__gte=time_threshold).first()
            if existing_record:
                logger.warning(
                    f"[DUPLICATE_RECORD] detected for machine {machine_name} at proc_time {proc_time}. Skipping save. msg: {payload}")
            else:
                logger.info(f"[mqtt_msg_saved_MOLD_{camera.name}_{machine.id}_{str(status)}]: {payload}")
                trigger_similarity = payload.get('trigger_matching_similarity')
                trigger_similarity_0 = trigger_similarity.get('0') if trigger_similarity else None
                trigger_similarity_1 = trigger_similarity.get('1') if trigger_similarity else None
                DMold.objects.create(
                    status=str(status),
                    trigger_similarity_0=trigger_similarity_0,
                    trigger_similarity_1=trigger_similarity_1,
                    proc_time=proc_time,
                    camera=camera,
                    machine=machine
                )
        elif 'airbag' in machine_name:
            existing_record = DAirbag.objects.filter(proc_time=proc_time, camera=camera, machine=machine,
                                                     status=status, timestamp__gte=time_threshold).first()
            if existing_record:
                logger.warning(
                    f"[DUPLICATE_RECORD] detected for machine {machine_name} at proc_time {proc_time}. Skipping save. msg: {payload}")
            else:
                logger.info(f"[mqtt_msg_saved_AIRBAG_{camera.name}_{machine.id}_{str(status)}]: {payload}")
                DAirbag.objects.create(
                    status=str(status),
                    proc_time=proc_time,
                    camera=camera,
                    machine=machine
                )
        elif 'reel-packaging' in machine_name:
            existing_record = DReelPackaging.objects.filter(proc_time=proc_time, camera=camera, machine=machine,
                                                            status=status, timestamp__gte=time_threshold).first()
            if existing_record:
                logger.warning(
                    f"[DUPLICATE_RECORD] detected for machine {machine_name} at proc_time {proc_time}. Skipping save. msg: {payload}")
            else:
                logger.info(f"[mqtt_msg_saved_REEL_{camera.name}_{machine.id}_{str(status)}]: {payload}")
                DReelPackaging.objects.create(
                    status=str(status),
                    proc_time=proc_time,
                    camera=camera,
                    machine=machine
                )
        elif 'pcb' in machine_name:
            existing_record = DPcb.objects.filter(proc_time=proc_time, camera=camera, machine=machine,
                                                  status=status, timestamp__gte=time_threshold).first()
            if existing_record:
                logger.warning(
                    f"[DUPLICATE_RECORD] detected for machine {machine_name} at proc_time {proc_time}. Skipping save. msg: {payload}")
            else:
                logger.info(f"[mqtt_msg_saved_PCB_{camera.name}_{machine.id}_{str(status)}]: {payload}")
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
            existing_record = DPinArrival.objects.filter(proc_time=proc_time, camera=camera, machine=machine,
                                                         status=status, timestamp__gte=time_threshold).first()
            if existing_record:
                logger.warning(
                    f"[DUPLICATE_RECORD] detected for machine {machine_name} at proc_time {proc_time}. Skipping save. msg: {payload}")
            else:
                logger.info(f"[mqtt_msg_saved_PIN_{camera.name}_{machine.id}_{str(status)}]: {payload}")
                DPinArrival.objects.create(
                    status=str(status) if status is not None else None,
                    proc_time=proc_time,
                    camera=camera,
                    machine=machine
                )
        else:
            logger.warning(f"\nWrong machine data was retrieved from mqtt, msg: {msg.topic}!!!\n")

        # msg_processing_time = timezone.now() - msg_received_time
        # logger.info(f"Time spent for msg processing: {msg_processing_time.total_seconds():.4f} seconds")

    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from MQTT message: {e}, msg: {msg.topic}")
    except Exception as e:
        logger.error(f"An error occurred: {e}, msg: {msg.topic}")


def on_disconnect(client, userdata, rc):
    logger.info(f"Disconnected with result code {rc}. Reconnecting...")
    mqtt_state = MqttClientState.objects.first()
    if mqtt_state:
        mqtt_state.status = "AVAIL"
        mqtt_state.save()
        logger.info(f"MQTT service client disconnected and state change to {mqtt_state.status}")
    if rc != 0:
        mqtt_state.status = "BUSY"
        mqtt_state.save()
        logger.info(f"Attempting to reconnect, state changed to {mqtt_state.status}")
        client.reconnect()


def is_management_command():
    return any(arg in sys.argv for arg in ["collectstatic", "migrate", "runserver", "makemigrations", "test"])


def start_mqtt_client():
    global client
    if is_management_command():
        logging.info("Skipping MQTT service start during collectstatic.")
        return

    mqtt_state, _ = MqttClientState.objects.get_or_create(id=1, defaults={'status': 'AVAIL'})
    if mqtt_state and (mqtt_state.status == 'AVAIL'
                       or (timezone.now() - mqtt_state.last_updated) > timedelta(minutes=1)):
        if client is None:
            logger.info('Started mqtt client. Connecting...')
            client = mqtt.Client()
            client.on_connect = on_connect
            client.on_message = on_message
            mqtt_state.status = "BUSY"
            mqtt_state.save()
            logger.info(f"MQTT service client connected and state change to {mqtt_state.status}")
            # Connect to the broker (you can use settings from Django settings)
            broker_url = settings.MQTT_BROKER_URL
            broker_port = settings.MQTT_BROKER_PORT
            try:
                client.connect(broker_url, broker_port, 60)
                logger.info(f'Connected to broker at: {settings.MQTT_BROKER_URL}')
                # Start the loop in a non-blocking way
                client.loop_start()
                logger.info("MQTT client loop started.")
            except Exception as e:
                logger.error(f"Failed to connect to MQTT broker: {e}")
        else:
            logger.info("MQTT is already connected.")
    else:
        logger.info("MQTT client is already running [BUSY], skipping this client.")