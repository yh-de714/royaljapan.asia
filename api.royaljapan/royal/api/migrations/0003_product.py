# Generated by Django 5.0.6 on 2024-09-19 03:01

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_alter_user_email_alter_user_username'),
    ]

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('price_origin', models.IntegerField(default=0)),
                ('price_sell', models.IntegerField(default=0)),
                ('description', models.CharField(blank=True, default='', max_length=1000, null=True)),
                ('title', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('image', models.CharField(blank=True, default='', max_length=1000, null=True)),
                ('seller', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, related_name='fee_user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
