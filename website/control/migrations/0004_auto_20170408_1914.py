# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('control', '0003_remove_experiment_geni_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='experiment',
            name='geni_user',
            field=models.ForeignKey(default=None, to='control.GeniUser'),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='expe_name',
            field=models.CharField(default=None, max_length=30),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='goal',
            field=models.CharField(default=None, max_length=256),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='irb_officer_email',
            field=models.EmailField(default=None, max_length=254),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='researcher_address',
            field=models.CharField(default=None, max_length=64),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='researcher_email',
            field=models.EmailField(default=None, max_length=254),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='researcher_institution_name',
            field=models.CharField(default=None, max_length=30),
        ),
        migrations.AlterField(
            model_name='experiment',
            name='researcher_name',
            field=models.CharField(default=None, max_length=30),
        ),
    ]
