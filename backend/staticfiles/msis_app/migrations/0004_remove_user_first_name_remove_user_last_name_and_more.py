# Generated by Django 5.0.8 on 2024-09-20 10:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('msis_app', '0003_remove_dairbag_is_deleted_remove_dmold_is_deleted_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='first_name',
        ),
        migrations.RemoveField(
            model_name='user',
            name='last_name',
        ),
        migrations.AddField(
            model_name='user',
            name='name',
            field=models.CharField(default='No Name', max_length=50, null=True),
        ),
    ]
