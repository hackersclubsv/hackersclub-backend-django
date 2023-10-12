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


def send_email_ses(username, otp, email):
    ses = boto3.client("ses", region_name=settings.AWS_SES_REGION_NAME)
    try:
        response = ses.send_email(
            Destination={
                "ToAddresses": [email],
            },
            Message={
                "Body": {
                    "Html": {
                        "Charset": "UTF-8",
                        "Data": f"""
                            <p>Hello {username},</p>
                            <p>You requested a one-time password. Use this password to continue your process.</p>
                            <table width='100%'><tr><td style='text-align: center; font-size: 28px; font-weight: bold;'>{otp}</td></tr></table>
                            <p>If you didn't request this email, please ignore it.</p>
                            <p>-- Northeastern University Silicon Valley HackersClub</p>
                        """,
                    },
                },
                "Subject": {
                    "Charset": "UTF-8",
                    "Data": "Your one-time password",
                },
            },
            Source=settings.AWS_SES_EMAIL_SOURCE,
        )
    except (BotoCoreError, ClientError) as error:
        return {"success": False, "message": str(error)}
    else:
        return {"success": True, "message": response["MessageId"]}


def send_email_sendgrid(username, otp, email):
    # Set up data for dynamic template
    data = {"name": username, "otp": otp}

    # Prepare the message
    message = Mail(
        from_email=settings.SENDGRID_EMAIL_SOURCE,
        to_emails=email,
    )
    message.template_id = "d-fe0c2e98d91d4f97a40f083e6a832925"
    message.dynamic_template_data = data
    print(message)
    # Send the email using SendGrid
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        response = sg.send(message)
        print(response)
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
