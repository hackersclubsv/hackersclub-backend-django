import os
import random

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings
from django.core.files.storage import default_storage


def generate_otp():
    return str(random.randint(100000, 999999))


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


def handle_post_image_upload(user, post, file, idx=None):
    """
    Handle the image upload for a post instance.
    """
    filename, file_extension = os.path.splitext(file.name)
    filename = f"{filename}{idx}" if idx else filename
    s3_path = f"users/{user.id}/posts/{post.id}/{filename}{file_extension}"
    return save_file_to_s3(file, s3_path)


def handle_comment_image_upload(user, comment, file):
    """
    Handle the image upload for a comment instance.
    """
    _, file_extension = os.path.splitext(file.name)
    s3_path = f"users/{user.id}/comments/{comment.id}/image{file_extension}"
    return save_file_to_s3(file, s3_path)
