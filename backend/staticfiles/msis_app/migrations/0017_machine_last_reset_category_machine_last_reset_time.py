# Generated by Django 5.1 on 2024-10-29 08:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('msis_app', '0016_remove_machine_machines_name_a61b35_idx_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='machine',
            name='last_reset_category',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='machine',
            name='last_reset_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
