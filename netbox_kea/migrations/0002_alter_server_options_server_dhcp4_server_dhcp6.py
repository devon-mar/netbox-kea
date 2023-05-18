# Generated by Django 4.1.8 on 2023-05-15 04:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_kea', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='server',
            options={'ordering': ('name',)},
        ),
        migrations.AddField(
            model_name='server',
            name='dhcp4',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='server',
            name='dhcp6',
            field=models.BooleanField(default=True),
        ),
    ]