# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('control', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='battery',
            old_name='battery_if_present',
            new_name='if_battery_present',
        ),
        migrations.RenameField(
            model_name='sensor',
            old_name='expereiment_id',
            new_name='experiment_id',
        ),
        migrations.RemoveField(
            model_name='experiment',
            name='other_sensor',
        ),
        migrations.RemoveField(
            model_name='experiment',
            name='sensor_data_type',
        ),
        migrations.RemoveField(
            model_name='experiment',
            name='store_protect',
        ),
        migrations.AddField(
            model_name='sensor',
            name='frequency_unit',
            field=models.CharField(default=None, max_length=512, blank=True),
        ),
        migrations.AddField(
            model_name='sensor',
            name='truncation',
            field=models.IntegerField(default=None, blank=True),
        ),
    ]
