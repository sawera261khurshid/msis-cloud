from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import Machine, Camera
from mqtt_client.mqtt_service import add_subscription, remove_subscription
import logging

logger = logging.getLogger('signals')

@receiver(pre_save, sender=Machine)
def track_machine_changes(sender, instance, **kwargs):
    if instance.pk:
        # Existing instance, fetch the previous state
        try:
            previous_instance = Machine.objects.get(pk=instance.pk)
        except Machine.DoesNotExist:
            previous_instance = None

        if previous_instance:
            instance._previous_instance = previous_instance


@receiver(post_save, sender=Machine)
def add_machine_subscription(sender, instance, created, **kwargs):
    # logger.info(f"MACHINE CHANGES DETECTED: {instance.name}, {instance.is_deleted}")
    previous_instance = getattr(instance, '_previous_instance', None)
    prev_state = previous_instance.is_deleted if previous_instance else None

    if created or (previous_instance and instance.is_deleted == False and previous_instance.is_deleted != instance.is_deleted):
        logger.info(f"Machine {instance.name} was created or re-activated (prev state: is_deleted={prev_state}, now is_deleted: {instance.is_deleted}), so subscribing to {instance.name}/#")
        add_subscription(f'{instance.name}/#')
    elif instance.is_deleted:
        logger.info(f"Machine was deleted (prev state: is_deleted={prev_state}), so unsubscribe from the topic /{instance.name}/# ...")
        remove_subscription(f'{instance.name}/#')
    else:
        logger.info(f"Machine {instance.name} update was detected. PrevState:  is_deleted={prev_state}")

# @receiver(post_delete, sender=Machine)
# def remove_machine_subscription(sender, instance, **kwargs):
#     print(f'remove_machine_sub: {instance.name}/#')
#     remove_subscription(f'{instance.name}/#')


@receiver(pre_save, sender=Camera)
def track_camera_changes(sender, instance, **kwargs):
    if instance.pk:
        # Existing instance, fetch the previous state
        try:
            previous_instance = Camera.objects.get(pk=instance.pk)
        except Camera.DoesNotExist:
            previous_instance = None

        if previous_instance:
            instance._previous_instance = previous_instance

@receiver(post_save, sender=Camera)
def add_camera_subscription(sender, instance, created, **kwargs):
    # logger.info(f"CAMERA CHANGES DETECTED: {instance.name}, {instance.is_deleted}")
    previous_instance = getattr(instance, '_previous_instance', None)
    if created or (previous_instance and instance.is_deleted == False and previous_instance.is_deleted != instance.is_deleted):
        logger.info(f"Camera {instance.name} was created or re-activated, so subscribing to /{instance.machine}/{instance.name}")
        add_subscription(f'{instance.machine}/{instance.name}')
    elif instance.is_deleted:
        logger.info(f"Camera was deleted, so unsubscribe from the topic {instance.machine}/{instance.name} ...")
        remove_subscription(f'{instance.machine}/{instance.name}')
    else:
        logger.info(f"Camera {instance.name} update was detected.")

# @receiver(post_delete, sender=Camera)
# def remove_camera_subscription(sender, instance, **kwargs):
#     print(f"remove_camera_sub: machine: {instance.machine}, {instance.name}")
#     remove_subscription(f'{instance.machine}/{instance.name}')
