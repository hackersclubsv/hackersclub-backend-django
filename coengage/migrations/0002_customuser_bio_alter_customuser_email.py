# Generated by Django 4.2.3 on 2023-07-22 02:52

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("coengage", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="bio",
            field=models.TextField(blank=True, max_length=500, verbose_name="about"),
        ),
        migrations.AlterField(
            model_name="customuser",
            name="email",
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
