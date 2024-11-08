# from celery import shared_task
# from django.utils import timezone
# from .models import Factory, Machine, DAirbag, DMold, DPcb, DPinArrival, DReelPackaging
# from django.db.models import Count, Case, When, IntegerField
# from collections import defaultdict

# @shared_task
# def update_factory_reset_timestamps():
#     current_time = timezone.now()
#     factories = Factory.objects.all()

#     # Prepare model classes mapping
#     model_classes = {
#         'airbag': DAirbag,
#         'mold': DMold,
#         'pcb': DPcb,
#         'pin': DPinArrival,
#         'reel-packaging': DReelPackaging,
#     }

#     # Reset counts for all factories
#     counts_data = defaultdict(lambda: {"anomaly_count": 0, "detection_count": 0})

#     for factory in factories:
#         factory.reset_timestamp = current_time
#         factory.save()
#         print("Factory reset timestamp updated to", current_time)

#         machines = Machine.objects.filter(factory=factory)

#         # Calculate detection and anomaly counts for each machine
#         for machine in machines:
#             reset_time = factory.reset_timestamp

#             # Use a temporary dictionary to store counts
#             temp_counts = {"anomaly_count": 0, "detection_count": 0}

#             # For each model class, aggregate counts since the last reset
#             for key, model_class in model_classes.items():
#                 anomalies = model_class.objects.filter(machine=machine, timestamp__gte=reset_time)

#                 # Calculate anomaly count
#                 anomaly_count = anomalies.aggregate(count=Count(Case(When(status='NG', then=1), output_field=IntegerField())))['count'] or 0

#                 # Calculate detection count
#                 detection_count = anomalies.aggregate(count=Count(Case(
#                     When(status='Normal', then=1),
#                     When(status='NG', then=1),
#                     output_field=IntegerField()
#                 )))['count'] or 0

#                 # Update the temporary counts
#                 temp_counts["anomaly_count"] += anomaly_count
#                 temp_counts["detection_count"] += detection_count

#             # Add the temporary counts to the overall counts data
#             counts_data[machine.id]["anomaly_count"] += temp_counts["anomaly_count"]
#             counts_data[machine.id]["detection_count"] += temp_counts["detection_count"]

#             # Log the counts for the machine
#             print(f"Machine: {machine.name}, Anomaly Count: {temp_counts['anomaly_count']}, Detection Count: {temp_counts['detection_count']}")

#     # Log counts for all machines before resetting them
#     for machine_id, counts in counts_data.items():
#         print(f"Before reset - Machine ID: {machine_id}, Anomaly Count: {counts['anomaly_count']}, Detection Count: {counts['detection_count']}")

#     # Reset counts to zero for the next 5-minute period
#     return counts_data  # Optionally return counts data if needed


from celery import shared_task
from django.utils import timezone
from .models import Factory, Machine, DAirbag, DMold, DPcb, DPinArrival, DReelPackaging
from django.db.models import Count, Case, When, IntegerField
from collections import defaultdict

@shared_task
def automatic_factory_reset_8am_and_8pm():
    current_time = timezone.now()
    factories = Factory.objects.all()

    # Prepare model classes mapping
    model_classes = {
        'airbag': DAirbag,
        'mold': DMold,
        'pcb': DPcb,
        'pin': DPinArrival,
        'reel-packaging': DReelPackaging,
    }

    # Reset counts for all factories
    counts_data = defaultdict(lambda: {"anomaly_count": 0, "detection_count": 0})

    for factory in factories:
        factory.reset_timestamp = current_time
        factory.save()
        print("Factory reset timestamp updated to", current_time)

        machines = Machine.objects.filter(factory=factory)

        # Calculate detection and anomaly counts for each machine
        for machine in machines:
            reset_time = factory.reset_timestamp

            # Use a temporary dictionary to store counts
            temp_counts = {"anomaly_count": 0, "detection_count": 0}

            # For each model class, aggregate counts since the last reset
            for key, model_class in model_classes.items():
                anomalies = model_class.objects.filter(machine=machine, timestamp__gte=reset_time)

                # Calculate anomaly count
                anomaly_count = anomalies.aggregate(count=Count(Case(When(status='NG', then=1), output_field=IntegerField())))['count'] or 0

                # Calculate detection count
                detection_count = anomalies.aggregate(count=Count(Case(
                    When(status='Normal', then=1),
                    When(status='NG', then=1),
                    output_field=IntegerField()
                )))['count'] or 0

                # Update the temporary counts
                temp_counts["anomaly_count"] += anomaly_count
                temp_counts["detection_count"] += detection_count

            # Add the temporary counts to the overall counts data
            counts_data[machine.id]["anomaly_count"] += temp_counts["anomaly_count"]
            counts_data[machine.id]["detection_count"] += temp_counts["detection_count"]

            # Log the counts for the machine
            print(f"Machine: {machine.name}, Anomaly Count: {temp_counts['anomaly_count']}, Detection Count: {temp_counts['detection_count']}")

    # Log counts for all machines before resetting them
    for machine_id, counts in counts_data.items():
        print(f"Before reset - Machine ID: {machine_id}, Anomaly Count: {counts['anomaly_count']}, Detection Count: {counts['detection_count']}")

    # Reset counts to zero for the next period
    return counts_data  # Optionally return counts data if needed
