# Generated by Django 5.0.8 on 2024-10-14 13:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('msis_app', '0012_remove_camera_cameras_machine_795ef2_idx_and_more'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='dairbag',
            name='d_airbag_machine_2ea8ff_idx',
        ),
        migrations.RemoveIndex(
            model_name='dairbag',
            name='d_airbag_camera__ebbfd3_idx',
        ),
        migrations.RemoveIndex(
            model_name='dairbag',
            name='d_airbag_timesta_bea790_idx',
        ),
        migrations.RemoveIndex(
            model_name='dairbag',
            name='d_airbag_status_07e0f8_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpcb',
            name='d_pcb_machine_6ecc84_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpcb',
            name='d_pcb_camera__b47058_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpcb',
            name='d_pcb_timesta_e51b78_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpcb',
            name='d_pcb_status_171670_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpinarrival',
            name='d_pin_arriv_machine_c66a22_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpinarrival',
            name='d_pin_arriv_camera__4471d5_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpinarrival',
            name='d_pin_arriv_timesta_675bc9_idx',
        ),
        migrations.RemoveIndex(
            model_name='dpinarrival',
            name='d_pin_arriv_status_a360c0_idx',
        ),
        migrations.RemoveIndex(
            model_name='dreelpackaging',
            name='d_reel_pack_machine_19da5d_idx',
        ),
        migrations.RemoveIndex(
            model_name='dreelpackaging',
            name='d_reel_pack_camera__accecf_idx',
        ),
        migrations.RemoveIndex(
            model_name='dreelpackaging',
            name='d_reel_pack_timesta_588f93_idx',
        ),
        migrations.RemoveIndex(
            model_name='dreelpackaging',
            name='d_reel_pack_status_0d6410_idx',
        ),
        migrations.RemoveIndex(
            model_name='factory',
            name='factories_name_5d066a_idx',
        ),
        migrations.RemoveIndex(
            model_name='factory',
            name='factories_is_dele_805252_idx',
        ),
        migrations.RemoveIndex(
            model_name='machine',
            name='machines_name_77122a_idx',
        ),
        migrations.RemoveIndex(
            model_name='machine',
            name='machines_factory_8a5607_idx',
        ),
        migrations.RemoveIndex(
            model_name='machine',
            name='machines_is_dele_c0650e_idx',
        ),
        migrations.RemoveIndex(
            model_name='user',
            name='users_usernam_baeb4b_idx',
        ),
        migrations.RemoveIndex(
            model_name='user',
            name='users_is_dele_21b557_idx',
        ),
        migrations.AddIndex(
            model_name='dairbag',
            index=models.Index(fields=['machine', 'camera', 'timestamp', 'status'], name='d_airbag_machine_38abcb_idx'),
        ),
        migrations.AddIndex(
            model_name='dpcb',
            index=models.Index(fields=['machine', 'camera', 'timestamp', 'status'], name='d_pcb_machine_1627a6_idx'),
        ),
        migrations.AddIndex(
            model_name='dpinarrival',
            index=models.Index(fields=['machine', 'camera', 'timestamp', 'status'], name='d_pin_arriv_machine_564294_idx'),
        ),
        migrations.AddIndex(
            model_name='dreelpackaging',
            index=models.Index(fields=['machine', 'camera', 'timestamp', 'status'], name='d_reel_pack_machine_0125f4_idx'),
        ),
        migrations.AddIndex(
            model_name='factory',
            index=models.Index(fields=['name', 'is_deleted'], name='factories_name_6d940e_idx'),
        ),
        migrations.AddIndex(
            model_name='machine',
            index=models.Index(fields=['name', 'factory', 'is_deleted'], name='machines_name_a61b35_idx'),
        ),
        migrations.AddIndex(
            model_name='user',
            index=models.Index(fields=['username', 'is_deleted'], name='users_usernam_f3de21_idx'),
        ),
    ]
