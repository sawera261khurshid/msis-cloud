# Generated by Django 5.1 on 2024-09-05 02:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('msis_app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='dairbag',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='dmold',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='dpcb',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='dpinarrival',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='dreelpackaging',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
    ]