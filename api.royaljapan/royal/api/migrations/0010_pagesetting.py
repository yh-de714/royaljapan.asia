# Generated by Django 5.0.6 on 2024-10-08 08:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_product_image1_product_image2_product_image3_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='PageSetting',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('key', models.CharField(blank=True, default='', max_length=32, null=True)),
                ('value', models.CharField(blank=True, default='', max_length=1000, null=True)),
            ],
        ),
    ]
