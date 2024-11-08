# Generated by Django 5.0.8 on 2024-09-02 18:12

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Camera',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('ref_id', models.IntegerField(blank=True, null=True)),
                ('name', models.CharField(max_length=255)),
                ('serial_no', models.IntegerField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_deleted', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'cameras',
            },
        ),
        migrations.CreateModel(
            name='Factory',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('location', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_deleted', models.BooleanField(default=False)),
            ],
            options={
                'verbose_name': 'Factory',
                'verbose_name_plural': 'Factories',
                'db_table': 'factories',
            },
        ),
        migrations.CreateModel(
            name='Machine',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('title', models.CharField(max_length=255)),
                ('ip_address', models.CharField(max_length=15)),
                ('location', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('factory', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='machine_factory', to='msis_app.factory')),
            ],
            options={
                'db_table': 'machines',
            },
        ),
        migrations.CreateModel(
            name='DReelPackaging',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.CharField(max_length=255)),
                ('proc_time', models.FloatField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('camera', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reel_packaging_camera_parameters', to='msis_app.camera')),
                ('machine', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reel_packaging_machine_parameter', to='msis_app.machine')),
            ],
            options={
                'verbose_name': 'Reel packaging',
                'verbose_name_plural': 'Reel packaging data',
                'db_table': 'd_reel_packaging',
            },
        ),
        migrations.CreateModel(
            name='DPinArrival',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.CharField(max_length=255)),
                ('proc_time', models.CharField(max_length=255, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('camera', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pin_arrival_camera_parameter', to='msis_app.camera')),
                ('machine', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pin_arrival_machine_parameter', to='msis_app.machine')),
            ],
            options={
                'verbose_name': 'Pin arrival',
                'verbose_name_plural': 'Pin arrival data',
                'db_table': 'd_pin_arrival',
            },
        ),
        migrations.CreateModel(
            name='DPcb',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.CharField(max_length=255)),
                ('trigger_similarity_0', models.FloatField(blank=True, null=True)),
                ('trigger_similarity_1', models.FloatField(blank=True, null=True)),
                ('proc_time', models.FloatField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('camera', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pcb_camera_parameters', to='msis_app.camera')),
                ('machine', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pcb_machine_parameter_machine', to='msis_app.machine')),
            ],
            options={
                'verbose_name': 'PCB',
                'verbose_name_plural': 'PCB data',
                'db_table': 'd_pcb',
            },
        ),
        migrations.CreateModel(
            name='DMold',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.CharField(max_length=255)),
                ('trigger_similarity_0', models.FloatField(blank=True, null=True)),
                ('trigger_similarity_1', models.FloatField(blank=True, null=True)),
                ('proc_time', models.FloatField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('camera', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mold_camera_parameter', to='msis_app.camera')),
                ('machine', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mold_machine_parameter', to='msis_app.machine')),
            ],
            options={
                'verbose_name': 'Mold',
                'verbose_name_plural': 'Mold data',
                'db_table': 'd_mold',
            },
        ),
        migrations.CreateModel(
            name='DAirbag',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.CharField(max_length=255)),
                ('proc_time', models.FloatField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('camera', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='airbag_camera_parameters', to='msis_app.camera')),
                ('machine', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='airbag_machine_parameters', to='msis_app.machine')),
            ],
            options={
                'verbose_name': 'Airbag',
                'verbose_name_plural': 'Airbag data',
                'db_table': 'd_airbag',
            },
        ),
        migrations.AddField(
            model_name='camera',
            name='machine',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='camera_machine_id', to='msis_app.machine'),
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=255, unique=True)),
                ('first_name', models.CharField(default=None, max_length=50, null=True)),
                ('last_name', models.CharField(default=None, max_length=50, null=True)),
                ('password', models.CharField(max_length=255)),
                ('email', models.EmailField(default=None, max_length=254, null=True, unique=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_activated', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_login', models.DateTimeField(auto_now=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('approved_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_approved', to=settings.AUTH_USER_MODEL)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_updated', to=settings.AUTH_USER_MODEL)),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
                ('factories', models.ManyToManyField(blank=True, related_name='users', to='msis_app.factory')),
                ('machines', models.ManyToManyField(blank=True, related_name='machines', to='msis_app.machine')),
            ],
            options={
                'db_table': 'users',
            },
        ),
    ]