# Generated by Django 5.0.6 on 2024-09-19 04:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_product'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='sold_count',
            field=models.IntegerField(default=0),
        ),
    ]
