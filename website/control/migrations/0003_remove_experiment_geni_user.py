# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('control', '0002_auto_20170407_1955'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='experiment',
            name='geni_user',
        ),
    ]
