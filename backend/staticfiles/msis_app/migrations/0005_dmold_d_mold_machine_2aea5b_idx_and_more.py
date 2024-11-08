# Generated by Django 5.0.8 on 2024-09-25 11:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('msis_app', '0004_remove_user_first_name_remove_user_last_name_and_more'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='dmold',
            index=models.Index(fields=['machine'], name='d_mold_machine_2aea5b_idx'),
        ),
        migrations.AddIndex(
            model_name='dmold',
            index=models.Index(fields=['camera'], name='d_mold_camera__c6e7cb_idx'),
        ),
        migrations.AddIndex(
            model_name='dmold',
            index=models.Index(fields=['timestamp'], name='d_mold_timesta_2286bb_idx'),
        ),
        migrations.AddIndex(
            model_name='dmold',
            index=models.Index(fields=['status'], name='d_mold_status_c2dee3_idx'),
        ),
    ]
