# Generated by Django 5.0.8 on 2024-09-25 12:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('msis_app', '0008_dreelpackaging_d_reel_pack_machine_19da5d_idx_and_more'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='dpcb',
            index=models.Index(fields=['machine'], name='d_pcb_machine_6ecc84_idx'),
        ),
        migrations.AddIndex(
            model_name='dpcb',
            index=models.Index(fields=['camera'], name='d_pcb_camera__b47058_idx'),
        ),
        migrations.AddIndex(
            model_name='dpcb',
            index=models.Index(fields=['timestamp'], name='d_pcb_timesta_e51b78_idx'),
        ),
        migrations.AddIndex(
            model_name='dpcb',
            index=models.Index(fields=['status'], name='d_pcb_status_171670_idx'),
        ),
    ]
