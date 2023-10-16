import os
import random

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings
from django.core.files.storage import default_storage
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from coengage.models import Comment, Image, Post


def generate_otp():
    return str(random.randint(100000, 999999))


def normalize_name(name):
    return name.strip().lower()


def send_email_sendgrid(username, otp, email):
    # Set up data for dynamic template
    data = {"name": username, "otp": otp}

    # Prepare the message
    message = Mail(
        from_email=settings.SENDGRID_EMAIL_SOURCE,
        to_emails=email,
    )
    message.template_id = settings.SENDGRID_TEMPLATE_ID
    message.dynamic_template_data = data

    # Send the email using SendGrid
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        response = sg.send(message)

    except Exception as e:
        return {"success": False, "message": str(e)}
    else:
        return {"success": True, "message": "Email sent successfully"}


def save_file_to_s3(file, s3_path):
    """
    Save a given file to the specified S3 path.
    """
    default_storage.save(s3_path, file)
    return default_storage.url(s3_path)


def handle_user_profile_picture_upload(user, file):
    """
    Handle the profile picture upload for a user instance.
    """
    _, file_extension = os.path.splitext(file.name)
    s3_path = f"users/{user.id}/profile_picture{file_extension}"
    return save_file_to_s3(file, s3_path)


def handle_image_upload(user, instance, file, idx=None):
    """
    Handle the image upload for an instance (either Post or Comment).
    """
    instance_type = "posts" if isinstance(instance, Post) else "comments"
    filename, file_extension = os.path.splitext(file.name)
    filename = f"{filename}{idx}" if idx else filename
    s3_path = (
        f"users/{user.id}/{instance_type}/{instance.id}/{filename}{file_extension}"
    )
    return save_file_to_s3(file, s3_path)


def handle_and_save_images(request, instance, field_name):
    if field_name in request.FILES:
        for idx, img_file in enumerate(request.FILES.getlist(field_name)):
            s3_url = handle_image_upload(request.user, instance, img_file, idx)
            if isinstance(instance, Post):
                Image.objects.create(url=s3_url, post=instance)
            elif isinstance(instance, Comment):
                Image.objects.create(url=s3_url, comment=instance)
